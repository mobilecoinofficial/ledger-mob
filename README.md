# Ledger Mobilecoin

A [MobileCoin][1] NanoApp for [Ledger][2] `nanosplus` and `nanox` devices.
You can grab the latest (unsigned) firmware and tooling [here](https://github.com/mobilecoinofficial/ledger-mob/releases), or follow the [Getting Started](#Getting-Started) instructions to build your own.

For application interaction or integration see the [library](https://mobilecoinofficial.github.io/ledger-mob/ledger_mob/index.html) and [APDU](https://mobilecoinofficial.github.io/ledger-mob/ledger_mob_apdu/index.html) documentation.

## Status

**This software is pre-release and under active development**

[![CI](https://github.com/mobilecoinofficial/ledger-mob/actions/workflows/rust.yml/badge.svg)](https://github.com/mobilecoinofficial/ledger-mob/actions/workflows/rust.yml)
[![GitHub tag](https://img.shields.io/github/tag/mobilecoinofficial/ledger-mob.svg)](https://github.com/mobilecoinofficial/ledger-mob)

Supported Wallets:

- [ ] MobileCoin Desktop (WIP) 


## Usage

### Attention

This repository contains pre-release and unaudited firmware releases for development and testing purposes only, use with caution.

End users should install signed and security-audited releases via [Ledger Live](https://www.ledger.com/ledger-live) for use with real funds, and use a supported wallet application for building and signing transactions.


### Installing pre-built binaries

Note that side-loading is only supported on `nanosplus` devices with firmware version `1.1.0`, and should only be used for development purposes.

- Download the latest nanosplus release [here](https://github.com/mobilecoinofficial/ledger-mob/releases/latest/download/ledger-mob-fw-nanosplus.tgz)
- `tar -xvf ledger-mob-fw-nanosplus.tgz` to extract the firmware package
- `ledgerctl install app_nanosplus.json` to install the nanoapp
  - You may need to add the `-f` argument to correctly unload prior releases


## Building and Testing

The project contains a top-level [Makefile](Makefile) exposing common functions, as well as a [`.envrc`](.envrc) file to export common environmental variables.

### Project Layout

- [apdu](./apdu) provides APDU / protocol definitions for communication with a hardware wallet
- [core](./core) contains platform-independent hardware wallet engine, used by `fw` and `lib`
- [fw](./fw) contains ledger firmware for `nanosplus` and `nanox` targets
- [lib](./lib) provides a library for interacting with the MobileCoin NanoApp and a CLI for basic interaction.
- [tests](./tests) provides high-level functional tests, used in `core` and `lib`, as well as a CLI for manually exercising these against the simulator or a physical device.
- [vendor](./vendor) contains forked and vendored dependencies, with the intent that these will be removed as contributions are merged upstream.
- [sim](./sim) provides helpers for executing Ledger's [Speculos][4] simulator locally or via docker container.


### Dependencies

You will need [rust](https://rustup.rs/) (nightly), [docker](https://docs.docker.com/get-docker/), and a collection of libraries / tools to build the project...

**Required:**
- `rustup default nightly` to default to nightly toolchain
- `rustup component add rust-src` to support out-of-tree targets
- `apt install make pkg-config clang gcc-multilib gcc-arm-none-eabi` to fetch build tools
- `apt install libusb-1.0-0-dev libhidapi-dev libudev-dev` for communication with physical ledger devices
- `docker pull ghcr.io/ledgerhq/speculos` to fetch speculos docker image for integration tests

On linux you will need to install the [udev rules](https://github.com/LedgerHQ/udev-rules)
- `wget https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/20-hw1.rules` to download the rules
- `sudo cp 20-hw1.rules /etc/udev/rules.d/` to move the rules to the right place
- `sudo udevadm control --reload-rules` to reload udev rules
- replug the device

**Optional:**
- `pip3 install ledgerwallet` to install the [ledgerctl](https://github.com/LedgerHQ/ledgerctl) tool to side-load applications onto a physical nanosplus
- [speculos](https://speculos.ledger.com/) to run the local simulator
  - see [here](https://speculos.ledger.com/installation/build.html) for speculos-specific dependencies
  - `make speculos` to build the vendored speculos module
- `apt insall direnv` to install [direnv](https://direnv.net/) (then [set up your shell](https://direnv.net/docs/hook.html)) to automatically load environmental variables
  - otherwise see [`.envrc`](.envrc)

### Building

A top level [Makefile](Makefile) exposes common functions for building / testing the project.

- `make fw` to build `nanosplus` and `nanox` firmware
- `make lib` to build the library and CLI
- `make tests` to build and run all tests
- `make nanosplus-run` or `make nanosx-run` to build and run the firmware under speculos
- `make nanosplus-load` to build firmware and load onto a `nanosplus` device (it is not possible to sideload onto the `nanox`)
- `make nanosplus-test` or `make nanosx-test` to run integration tests via the simulator
- `make lint` to check `cargo fmt` and `cargo clippy` lints

For more detail you might like to look at [`.github/workflows/rust.yml`](.github/workflows/rust.yml)


### Testing

Integration are build into the `lib` package, using speculos with `MODEL=nanosplus` by default.
Please note that if invoking this via `cargo test` you _must_ rebuild the relevant firmware manually.

Integration tests may also be executed against the simulator or physical device using the `ledger-mob-tests` tool.
Note that test targets _must_ be configured with the appropriate SLIP-0010/BIP-0039 mnemonic for a given test vector.

To exercise all functionality on a physical nanosplus (from the `tests` directory):

- `cargo run -- --target hid wallet-keys` to check root key derivation
- `cargo run -- --target hid subaddress-keys` to check subaddress key derivation
- `cargo run -- --target hid memo-sign` to check memo signing
- `cargo run -- --target hid tx --input vectors/tx1.json` will execute a block version 2 transaction (no summary) on the attached ledger device
- `cargo run -- --target hid tx --input vectors/tx3.json` will execute a block version >=3 transaction (with summary) on the attached ledger device

See `ledger-mob-tests --help` for more tests and configuration options.


## Contributing

### Bug Reports

The MobileCoin NanoApp is a prototype that is being actively developed.

Please report issues to https://github.com/mobilecoinofficial/ledger-mob/issues.

1. Search both open and closed tickets to make sure your bug report is not a duplicate.
1. Do not use github issues as a forum. To participate in community discussions, please use the community forum
   at [community.mobilecoin.foundation](https://community.mobilecoin.foundation).

### Pull Requests (PRs)

If you come across an issue / improvement feel free to submit a PR! Please make sure these are linted and tested locally prior to submission.
### Sign the Contributor License Agreement (CLA)

You will need to sign [our CLA](./CLA.md) before your pull request can be merged. Please
email [cla@mobilecoin.com](mailto:cla@mobilecoin.com) and we will send you a copy.


## Get in Touch

We're friendly. Feel free to [ping us](mailto:ledger-mob@mobilecoin.com)!


[1]: https://mobilecoin.com/
[2]: https://www.ledger.com/
[3]: https://direnv.net/
[4]: https://speculos.ledger.com/
