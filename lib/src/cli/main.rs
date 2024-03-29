// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Command line utility for interacting with the Ledger MobileCoin NanoApp

use std::{path::Path, time::Duration};

use clap::Parser;
use ledger_lib::{Device, Filters, LedgerProvider, Transport};
use log::{debug, error, info, LevelFilter};
use mc_transaction_extra::UnsignedTx;
use serde::{de::DeserializeOwned, Serialize};

use mc_crypto_keys::RistrettoPublic;
use mc_transaction_signer::{
    types::{TxSignReq, TxSignResp, TxSignSecrets},
    Operations,
};

use ledger_mob::DeviceHandle;
use ledger_mob_apdu::random::{RandomReq, RandomResp};

mod helpers;
use helpers::*;

/// Ledger command line utility
#[derive(Clone, PartialEq, Debug, Parser)]
struct Options {
    /// Supported transports for ledger discovery
    #[clap(long, value_enum, default_value = "any")]
    target: Filters,

    /// Device index (where more than one device is available)
    #[clap(long, default_value = "0")]
    device_index: usize,

    /// Subcommand to execute
    #[clap(subcommand)]
    cmd: Actions,

    /// Enable verbose logging
    #[clap(long, default_value = "info")]
    log_level: LevelFilter,
}

#[derive(Clone, PartialEq, Debug, Parser)]
#[non_exhaustive]
enum Actions {
    /// List available devices
    List,

    /// Fetch application info
    AppInfo,

    /// Fetch account keys
    Account {
        /// SLIP-0010 account index for SLIP-010 derivation
        #[clap(long, default_value = "0")]
        account: u32,
    },

    /// Fetch subaddress keys
    Subaddress {
        /// SLIP-0010 account index for SLIP-010 derivation
        #[clap(long, default_value = "0")]
        account: u32,

        /// Subaddress index
        #[clap(long)]
        subaddress: u64,
    },

    /// Resolve key images for transaction public keys
    KeyImage {
        /// SLIP-0010 account index for SLIP-010 derivation
        #[clap(long, default_value = "0")]
        account: u32,

        /// Subaddress index
        #[clap(long)]
        subaddress: u64,

        /// Transaction public key
        #[clap(long)]
        tx_public_key: HexData,
    },

    /// Fetch a random value from the device
    GetRandom,

    /// Fetch BIP0013/17 derived ed25519 public key (and optionally sign the provided challenge)
    Ident {
        /// URI for derived identity
        #[clap(long)]
        uri: String,

        /// index for derived identity
        #[clap(long, default_value = "0")]
        index: u32,

        /// hex-encoded challenge to be signed
        #[clap(long)]
        challenge: Option<HexData<32>>,
    },

    // Implement shared signer operations
    #[command(flatten)]
    Signer(Operations),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Options::parse();

    // Setup logging
    simplelog::SimpleLogger::init(args.log_level, simplelog::Config::default()).unwrap();

    // Connect to ledger device
    let mut p = LedgerProvider::init().await;

    debug!("Using transport: {:?}", args.target);

    // List available devices
    let devices = p.list(args.target).await?;
    if devices.is_empty() {
        return Err(anyhow::anyhow!("No devices found"));
    }

    // Handle list command
    if args.cmd == Actions::List {
        info!("Devices:");
        for (i, d) in devices.iter().enumerate() {
            info!("  {}: {}", i, d);
        }

        return Ok(());
    }

    // Select device by index
    if args.device_index >= devices.len() {
        return Err(anyhow::anyhow!(
            "Invalid device index: {} (max: {})",
            args.device_index,
            devices.len() - 1
        ));
    }

    debug!(
        "Using device {}: {}",
        args.device_index, devices[args.device_index]
    );

    // Connect to device
    let t = match p.connect(devices[args.device_index].clone()).await {
        Ok(v) => v.into(),
        Err(e) => {
            error!(
                "Failed to connect to device: {:04x?}",
                devices[args.device_index]
            );
            return Err(e.into());
        }
    };

    // Execute command
    if let Err(e) = execute(t, args.cmd).await {
        error!("Failed to execute command: {}", e);
        error!("(Please check you have the mobilecon app open and on the main screen)");
        return Err(anyhow::anyhow!("command failed"));
    }

    Ok(())
}

/// Execute a command with the provided transport
async fn execute<T>(mut t: DeviceHandle<T>, cmd: Actions) -> anyhow::Result<()>
where
    T: Device + Send,
{
    let mut buff = [0u8; 1024];

    debug!("Executing command: {:?}", cmd);

    match cmd {
        Actions::AppInfo => {
            let i = t.app_info().await?;

            info!("app info: {:#?}", i);
        }
        Actions::Account { account } => {
            info!("requesting root keys for wallet: {}", account);

            let r = t.account_keys(account).await?;

            info!("root view private key: {}", r.view_private_key());
            info!("root spend public key:  {}", r.spend_public_key());
        }
        Actions::Subaddress {
            account,
            subaddress,
        } => {
            info!(
                "requesting subaddress keys for wallet: {} subaddress: {}",
                account, subaddress
            );

            let r = t.subaddress_keys(account, subaddress).await?;

            info!("subaddress view private key: {}", r.view_private);
            info!("subaddress spend public key:  {}", r.spend_public);
        }
        Actions::KeyImage {
            account,
            subaddress,
            tx_public_key,
        } => {
            info!(
                "resolving key image for account {}:{} tx_public_key: {}",
                account,
                subaddress,
                tx_public_key.to_string(),
            );

            let tx_public_key = RistrettoPublic::try_from(tx_public_key.as_ref())
                .map_err(|_| anyhow::anyhow!("failed to parse ristretto public key from hex"))?;

            let key_image = t.key_image(account, subaddress, tx_public_key).await?;

            info!("key image: {}", key_image);
        }
        Actions::GetRandom => {
            info!("requesting random value");

            let r = t
                .request::<RandomResp>(RandomReq {}, &mut buff, Duration::from_secs(2))
                .await?;

            info!("value: {:x?}", r.value);
        }
        Actions::Ident {
            uri,
            index,
            challenge,
        } => {
            info!("Requesting identity for uri: '{}' (index: {})", uri, index);

            // Setup challenge
            let mut c: [u8; 32] = rand::random();
            if let Some(v) = challenge {
                c.copy_from_slice(v.as_ref());
            }

            info!("Using challenge: {}", hex::encode(c));

            // Execute identity request
            let (key, sig) = t.identity(index, &uri, &c).await?;

            // Display response
            info!("public key: {}", hex::encode(key.as_bytes()));
            info!("signature: {}", hex::encode(sig));
        }
        Actions::Signer(c) => {
            // Fetch account handle for signer operation
            let account_index = c.account_index();
            let a = t.account(account_index).await;

            // Handle signer operations
            match &c {
                Operations::GetAccount { output, .. } => {
                    Operations::get_account(&a, account_index, output)?
                }
                Operations::SyncTxos { input, output, .. } => {
                    Operations::sync_txos(&a, input, output)?
                }
                Operations::SignTx { input, output, .. } => {
                    // Read in transaction file
                    debug!("Loading unsigned transaction from '{}'", input);
                    let req: TxSignReq = read_input(input).await?;

                    // Fetch unblinding data
                    // TODO: remove this from mc-transaction-signer now we don't
                    // need to support block version 2
                    let tx_out_unblinding_data = match req.secrets {
                        TxSignSecrets::OutputSecrets(_) => panic!("Block version >3 support only"),
                        TxSignSecrets::TxOutUnblindingData(u) => u,
                    };

                    // Convert to unsigned TX
                    let unsigned = UnsignedTx {
                        tx_prefix: req.tx_prefix,
                        rings: req.rings,
                        tx_out_unblinding_data,
                        block_version: req.block_version,
                    };

                    // Sign transaction
                    let (tx, txos) = t.transaction(account_index, 60, unsigned).await?;

                    // Build sign response
                    let resp = TxSignResp {
                        account_id: req.account_id,
                        tx,
                        txos,
                    };

                    // Write output file
                    debug!("Writing signed transaction to '{}'", output);
                    write_output(output, &resp).await?;
                }
                _ => (),
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// Helper to read input files where required
async fn read_input<T: DeserializeOwned>(file_name: &str) -> anyhow::Result<T> {
    debug!("Reading input from '{}'", file_name);

    let s = tokio::fs::read_to_string(file_name).await?;

    // Determine format from file name
    let p = Path::new(file_name);

    // Decode based on input extension
    let v = match p.extension().and_then(|e| e.to_str()) {
        // Encode to JSON for `.json` files
        Some("json") => serde_json::from_str(&s)?,
        _ => return Err(anyhow::anyhow!("unsupported output file format")),
    };

    Ok(v)
}

/// Helper to write output files if `--output` argument is provided
async fn write_output(file_name: &str, value: &impl Serialize) -> anyhow::Result<()> {
    debug!("Writing output to '{}'", file_name);

    // Determine format from file name
    let p = Path::new(file_name);
    match p.extension().and_then(|e| e.to_str()) {
        // Encode to JSON for `.json` files
        Some("json") => {
            let s = serde_json::to_string(value)?;
            tokio::fs::write(p, s).await?;
        }
        _ => return Err(anyhow::anyhow!("unsupported output file format")),
    }

    Ok(())
}
