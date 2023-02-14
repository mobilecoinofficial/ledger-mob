RUSTARGS=--release


VERSION=$(shell git describe --dirty=+)

NANOSP_ARGS=
NANOX_ARGS=

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
	cargo test --package ledger-mob-core

nanosplus-test: nanosplus
	MODEL=nanosp cargo test --package ledger-mob $(NANOSP_ARGS)

nanox-test: nanox
	MODEL=nanox cargo test --package ledger-mob

# Build docs
docs:
	cargo doc --no-deps

# Build nanosplus firmware
nanosplus: 
	cd fw && cargo build --target ./nanosplus.json $(NANOSP_ARGS) $(RUSTARGS)

# Build nanox firmware
nanox:
	cd fw && cargo build --target ./nanox.json $(NANOX_ARGS) $(RUSTARGS)

# Run nanosplus firmware under speculos without debug
nanosplus-run:
	cd fw && cargo run --target ./nanosplus.json $(NANOSP_ARGS) $(RUSTARGS) -- $(SPECULOS_ARGS)

# Run nanox firmware under speculos without debug
nanox-run:
	cd fw && cargo run --target ./nanox.json $(NANOX_ARGS) $(RUSTARGS) -- $(SPECULOS_ARGS)

# Load firmware onto device
nanosplus-load: fw/target/nanosplus/release/ledger-mob-fw.hex
	cd fw/target/nanosplus/release/ && \
	ledgerctl install -f app_nanosplus.json

# Convert ELF to HEX for loading
fw/target/%/release/ledger-mob-fw.hex: %
	arm-none-eabi-objcopy fw/target/$</release/ledger-mob-fw -O ihex $@

# Package nanosplus nanoapp
package-nanosplus: fw/target/nanosplus/release/ledger-mob-fw.hex
	tar cvf ledger-mob-fw-nanosplus.tgz \
		-C fw/target/nanosplus/release \
		app_nanosplus.json \
		ledger-mob-fw.hex \
		mob14x14i.gif

# Package nanox nanoapp
package-nanox: fw/target/nanox/release/ledger-mob-fw.hex
	tar cvf ledger-mob-fw-nanosplus.tgz \
		-C target/nanox/release \
		app_nanox.json \
		ledger-mob-fw.hex \
		mob14x14i.gif


# Build speculos simulator
speculos: 
	cd vendor/speculos && mkdir -p build && cd build && cmake -DWITH_VNC=0 -DBUILD_TESTING=0 .. && make -j


# Run firmware under speculos with QEMU debug connection
nanosplus-debug:
	cd fw && speculos.py --model nanosp --display qt -k 1.0 --apdu-port 1237 --seed="$(MNEMONIC)" -d target/nanosplus/release/ledger-mob-fw

# Launch GDB connecting to speculos QEMU
nanosplus-gdb:
	cd fw && rust-gdb --tui fw/target/nanosplus/debug/ledger-mob-fw

# Objdump to show disassembly of sample_main (see `sp` for stack allocation)
objdump:
	arm-none-eabi-objdump fw/target/nanosplus/release/ledger-mob-fw --disassemble=sample_main -S | head -n 20

wts:
	whatthestack fw/target/nanosplus/release/ledger-mob-fw -n 15

# Run linters
lint: fmt clippy

fmt:
	cargo fmt --check -p ledger-mob -p -p ledger-mob-apdu ledger-mob-core -p ledger-mob-tests
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


.PHONY: fw lib core nanosplus nanox fmt clippy
