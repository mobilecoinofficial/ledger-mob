RUSTARGS=--release

VERSION=$(shell git describe --dirty=+)

# Docker image for building firmware
BUILD_CONTAINER="ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:5.4.1"

# Docker image for running speculos
SPECULOS_CONTAINER="ghcr.io/ledgerhq/speculos:latest"

SPECULOS_ARGS=
ifdef MNEMONIC
	SPECULOS_ARGS+=--seed "$(MNEMONIC)"
endif

# Supported devices, split by UI stack (BAGL buttons vs NBGL touch)
NANO_DEVICES=nanosplus nanox
TOUCH_DEVICES=stax flex apex_p
DEVICES=$(NANO_DEVICES) $(TOUCH_DEVICES)

# Devices that can be side-loaded (it is not possible to sideload onto the nanox)
LOADABLE_DEVICES=nanosplus $(TOUCH_DEVICES)

# Speculos model names, which differ from the cargo target name for the nanosplus
SPECULOS_MODEL_nanosplus=nanosp
SPECULOS_MODEL_nanox=nanox
SPECULOS_MODEL_stax=stax
SPECULOS_MODEL_flex=flex
SPECULOS_MODEL_apex_p=apex_p

# Touch devices need a VNC port to be interactive under speculos
SPECULOS_TOUCH_ARGS=--vnc-port 41000 --vnc-password abc123

all: fw lib

# Build all firmware
fw: nanosplus nanox

# Build lib / CLI
lib: 
	cd lib && cargo build

# Run tests
test: core-test nanosplus-test nanox-test

core-test:
	cargo nextest run --package ledger-mob-core

nanosplus-test: nanosplus
	MODEL=nanosplus cargo nextest run --package ledger-mob

nanox-test: nanox
	MODEL=nanox cargo nextest run --package ledger-mob

# Build docs
docs:
	cargo doc --no-deps --workspace

# Build firmware for a given device
$(DEVICES):
	docker run --rm -v $(shell pwd):/src -w /src/fw $(BUILD_CONTAINER) cargo ledger build $@

# Run nano firmware under speculos
$(addsuffix -run,$(NANO_DEVICES)): %-run:
	docker run --rm -v $(shell pwd):/src -p5000:5000 -p1237:1237 $(SPECULOS_CONTAINER) --model $(SPECULOS_MODEL_$*) --display headless --apdu-port 1237 --api-port 5000 $(SPECULOS_ARGS) /src/fw/target/$*/release/ledger-mob-fw

# Run touch firmware under speculos
$(addsuffix -run,$(TOUCH_DEVICES)): %-run:
	docker run --rm -v $(shell pwd):/src -p5000:5000 -p1237:1237 -p41000:41000 $(SPECULOS_CONTAINER) --model $(SPECULOS_MODEL_$*) --display headless --apdu-port 1237 --api-port 5000 $(SPECULOS_TOUCH_ARGS) $(SPECULOS_ARGS) /src/fw/target/$*/release/ledger-mob-fw

# Build firmware and load it onto an attached device
$(addsuffix -load,$(LOADABLE_DEVICES)): %-load:
	cd fw && cargo ledger build $* --load

# Convert ELF to HEX for loading
fw/target/%/release/ledger-mob-fw.hex: %
	arm-none-eabi-objcopy fw/target/$</release/ledger-mob-fw -O ihex $@

# Package nanoapp to archive
package-%: % fw/target/%/release/ledger-mob-fw.hex
	mkdir -p target/ledger-mob-fw-$<

	cp fw/target/$</release/ledger-mob-fw.hex target/ledger-mob-fw-$<
	cp fw/target/$</release/app_icon.gif target/ledger-mob-fw-$<

	tar cvf ledger-mob-fw-$<.tgz \
		-C target \
		ledger-mob-fw-$<

# Run firmware under speculos with QEMU debug connection
nanosplus-debug:
	docker run --rm -v $(shell pwd):/src -p5000:5000 -p1237:1237 $(SPECULOS_CONTAINER) --model nanosp --display headless --apdu-port 1237 --api-port 5000 $(SPECULOS_ARGS) -d target/nanosplus/release/ledger-mob-fw

# Launch GDB connecting to speculos QEMU
nanosplus-gdb:
	cd fw && rust-gdb target/nanosplus/release/ledger-mob-fw

# Objdump to show disassembly of sample_main (see `sp` for stack allocation)
objdump:
	arm-none-eabi-objdump fw/target/nanosplus/release/ledger-mob-fw --disassemble=sample_main -S | head -n 20

# Run linters
lint: fmt clippy

fmt:
	cargo fmt --check -p ledger-mob -p ledger-mob-apdu ledger-mob-core -p ledger-mob-tests
	cargo fmt --check --manifest-path=fw/Cargo.toml

clippy:
	cargo clippy -p ledger-mob -p ledger-mob-apdu -p ledger-mob-core -p ledger-mob-tests --no-deps -- -D warnings
# 	TODO: fix... something to do with target / build-std
#	cd fw && cargo clippy -p ledger-mob-fw --no-deps -- -D warnings

# Apply linters
fix: fmt-fix clippy-fix

fmt-fix:
	cargo fmt -p ledger-mob -p ledger-mob-apdu -p ledger-mob-core -p ledger-mob-tests
	cargo fmt --manifest-path=fw/Cargo.toml

clippy-fix:
	cargo clippy --fix --allow-dirty -p ledger-mob -p ledger-mob-apdu -p ledger-mob-core -p ledger-mob-tests --no-deps -- -D warnings
	cd fw && cargo clippy --fix --target nanosplus --allow-dirty -p ledger-mob-fw --no-deps -- -D warnings

# Run MIRI checks
# Notes:
#   - this requires a patched `mc-crypto-hashes` to disable `simd`
#   - `cargo clean` must be run to clear non-miri objects
#   - only specific tests with miri support are enabled
miri:
	cd core && cargo miri nextest run --no-default-features --features alloc,mlsag,ident,memo,summary -j4 -- miri_function tx_summary ring_sign test_sign

clean:
	rm -rf target fw/target

# NOTE: `package-%` is deliberately absent -- make skips implicit/pattern rule
# matching for phony targets, which would break it.
.PHONY: fw lib core fmt clippy clean docs $(DEVICES) \
	$(addsuffix -run,$(DEVICES)) $(addsuffix -load,$(LOADABLE_DEVICES))
