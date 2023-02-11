// Copyright (c) 2022-2023 The MobileCoin Foundation

use std::error::Error;

use clap::{clap_derive::ArgEnum, Parser};
use ledger_mob_tests::transaction::TransactionExpectation;
use log::{debug, info, LevelFilter};
use strum::{Display, EnumString, EnumVariantNames};

use ledger_transport::Exchange;
use ledger_transport_hid::TransportNativeHID;
use ledger_transport_tcp::{TcpOptions, TransportTcp};

use mc_core::slip10::{Language, Mnemonic};

/// Test CLI arguments
#[derive(Clone, Debug, Parser)]
pub struct Opts {
    #[clap(subcommand)]
    pub test: Tests,

    /// Target for test execution
    #[clap(long, value_enum, default_value = "tcp", env)]
    pub target: Target,

    /// bip39 Mnemonic (must be shared between test util and target)
    #[clap(long, env, value_parser=mnemonic_from_str)]
    pub mnemonic: Mnemonic,

    /// Log level
    #[clap(long, default_value = "debug", env)]
    pub log_level: LevelFilter,

    /// Enable logging for transports
    #[clap(long)]
    pub log_transports: bool,
}

pub fn mnemonic_from_str(s: &str) -> anyhow::Result<Mnemonic> {
    let m = Mnemonic::from_phrase(s, Language::English)?;
    Ok(m)
}

/// Test modes
#[derive(Clone, PartialEq, Debug, Parser, Display, EnumString, EnumVariantNames)]
pub enum Tests {
    /// Test wallet key derivation
    WalletKeys,
    /// Test subaddress key derivation
    SubaddressKeys {
        /// Number of subaddresses to derive
        #[clap(long, default_value = "16")]
        n: u64,
    },
    /// Test Memo HMAC / signing
    MemoSign,
    /// Test MLSAG signing
    Mlsag {
        /// Number of entries in the ring
        #[clap(long, default_value = "11")]
        ring_size: usize,
    },
    /// Test full transaction
    Tx {
        /// Unsigned transaction input
        /// (MUST match configured mnemonic)
        #[clap(long)]
        input: String,
    },
}

/// Test target connection
#[derive(Clone, PartialEq, Debug, ArgEnum, Display, EnumString, EnumVariantNames)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum Target {
    /// USB-HID connection for physical ledger devices
    Hid,
    /// TCP connection for speculos simulator
    Tcp,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load command line options
    let opts = Opts::parse();

    // Setup logging
    let mut c = simplelog::ConfigBuilder::new();
    if !opts.log_transports {
        c.add_filter_ignore_str("ledger_transport_tcp");
    }

    let _ = simplelog::SimpleLogger::init(opts.log_level, c.build());

    debug!("options: {:?}", opts);

    info!("Running test '{}` via {}", opts.test, opts.target);

    // Connect to target and execute test
    match opts.target {
        #[cfg(feature = "transport_tcp")]
        Target::Tcp => {
            let t = TransportTcp::new(TcpOptions::default()).await?;

            execute(t, opts).await?;
        }
        #[cfg(feature = "transport_hid")]
        Target::Hid => {
            let h = hidapi::HidApi::new()?;

            let devices: Vec<_> = TransportNativeHID::list_ledgers(&h).collect();
            debug!("Found devices: {:?}", devices);

            let t = TransportNativeHID::new(&h)?;

            execute(t, opts).await?;
        }
        #[cfg(any(not(feature = "transport_tcp"), not(feature = "transport_hid")))]
        _ => {
            return Err(anyhow::anyhow!(
                "transport: {} feature not enabled",
                opts.target
            ));
        }
    };

    log::info!("Test OK!");

    Ok(())
}

/// Execute a test with the provided transport
async fn execute<T, E>(target: T, opts: Opts) -> anyhow::Result<()>
where
    T: Exchange<Error = E> + Send + Sync,
    E: Error + Send + Sync + 'static,
{
    use ledger_mob_tests::*;

    match opts.test {
        Tests::WalletKeys => wallet::test(target, || async {}, opts.mnemonic).await?,
        Tests::SubaddressKeys { n } => {
            subaddress::test(target, || async {}, opts.mnemonic, n).await?
        }
        Tests::MemoSign => memo::hmac(target, opts.mnemonic, 0).await?,
        Tests::Mlsag { ring_size } => {
            mlsag::test(target, || async {}, opts.mnemonic, ring_size).await?
        }
        Tests::Tx { input } => {
            let v = std::fs::read_to_string(input)?;
            transaction::test(
                target,
                || async {},
                &TransactionExpectation {
                    mnemonic: opts.mnemonic.phrase(),
                    request: &v,
                },
            )
            .await?
        }
    }

    Ok(())
}
