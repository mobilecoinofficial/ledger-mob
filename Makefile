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

# Build nanosplus firmware
nanosplus: 
	docker run --rm -v $(shell pwd):/src -w /src/fw $(BUILD_CONTAINER) cargo ledger build nanosplus

# Build nanox firmware
nanox:
	docker run --rm -v $(shell pwd):/src -w /src/fw $(BUILD_CONTAINER) cargo ledger build nanox

# Run nanosplus firmware under speculos
nanosplus-run:
	docker run --rm -v $(shell pwd):/src -p5000:5000 -p1237:1237 $(SPECULOS_CONTAINER) --model nanosp --display headless --apdu-port 1237 --api-port 5000 $(SPECULOS_ARGS) /src/fw/target/nanosplus/release/ledger-mob-fw

# Run nanox firmware under speculos
nanox-run:
	docker run --rm -v $(shell pwd):/src -p5000:5000 -p1237:1237 $(SPECULOS_CONTAINER) --model nanox --display headless --apdu-port 1237 --api-port 5000 $(SPECULOS_ARGS) /src/fw/target/nanox/release/ledger-mob-fw

# Load firmware onto device
nanosplus-load: nanosplus
	cd fw && cargo ledger --use-prebuilt target/nanosplus/release/ledger-mob-fw build nanosplus --load

# Convert ELF to HEX for loading
fw/target/%/release/ledger-mob-fw.hex: %
	arm-none-eabi-objcopy fw/target/$</release/ledger-mob-fw -O ihex $@

# Package nanoapp to archive
package-%: % fw/target/%/release/ledger-mob-fw.hex
	mkdir -p target/ledger-mob-fw-$<

	cp fw/target/$</release/ledger-mob-fw.hex target/ledger-mob-fw-$<
	cp fw/target/$</release/app_$<.json target/ledger-mob-fw-$<
	cp fw/target/$</release/mob14x14i.gif target/ledger-mob-fw-$<

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

.PHONY: fw lib core nanosplus nanox fmt clippy clean docs
