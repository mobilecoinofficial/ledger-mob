// Copyright (c) 2022-2023 The MobileCoin Foundation

use clap::{Parser};
use log::{debug, info, LevelFilter, error};
use strum::{Display, EnumString, EnumVariantNames};

use ledger_transport::Exchange;

use mc_core::slip10::{Language, Mnemonic};
use ledger_mob::{Error, LedgerProvider, Filter, transport::GenericTransport, Connect};
use ledger_mob_tests::transaction::TransactionExpectation;


/// Test CLI arguments
#[derive(Clone, Debug, Parser)]
pub struct Opts {
    #[clap(subcommand)]
    pub test: Tests,

    /// Target for test execution
    #[clap(long, value_enum, default_value = "tcp", env)]
    pub target: Filter,

    /// Device index (where more than one device is available)
    #[clap(long, default_value = "0")]
    device_index: usize,

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
    /// List available devices (not a test)
    List,
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

    info!("Running test '{}` via {}", opts.test, opts.target);

    // Connect to ledger device
    let p = LedgerProvider::new()?;

    // List available devices
    let devices = p.list_devices(opts.target).await;
    if devices.is_empty() {
        return Err(anyhow::anyhow!("No devices found"));
    }

    // Handle list command
    if opts.test == Tests::List {
        info!("Devices:");
        for (i, d) in devices.iter().enumerate() {
            info!("  {}: {}", i, d);
        }

        return Ok(());
    }

    // Select device by index
    if opts.device_index >= devices.len() {
        return Err(anyhow::anyhow!(
            "Invalid device index: {} (max: {})",
            opts.device_index,
            devices.len() - 1
        ));
    }

    debug!(
        "Using device {}: {}",
        opts.device_index, devices[opts.device_index]
    );

    // Connect to device
    let t = match Connect::<GenericTransport>::connect(&p, &devices[opts.device_index]).await {
        Ok(v) => v,
        Err(e) => {
            error!(
                "Failed to connect to device: {:04x?}",
                devices[opts.device_index]
            );
            return Err(e.into());
        }
    };

    // Execute test
    if let Err(e) = execute(t, opts).await {
        error!("Failed to execute test: {}", e);
        error!("(Please check you have the mobilecon app open and on the main screen)");
        return Err(anyhow::anyhow!("test failed"));
    }

    log::info!("Test OK!");

    Ok(())
}

/// Execute a test with the provided transport
async fn execute<T>(target: T, opts: Opts) -> anyhow::Result<()>
where
    T: Exchange<Error = Error> + Send + Sync,
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
        Tests::List => unreachable!(),
    }

    Ok(())
}
