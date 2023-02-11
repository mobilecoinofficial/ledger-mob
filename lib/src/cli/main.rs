// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Command line utility for interacting with the Ledger MobileCoin NanoApp

use std::{error::Error, path::Path};

use clap::Parser;
use ledger_transport::Exchange;
use log::{debug, error, info, LevelFilter};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Serialize};
use strum::Display;

use mc_core::keys::TxOutPublic;
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::ring_ct::InputRing;
use mc_transaction_core::tx::Tx;
use mc_transaction_signer::{
    types::{TxSignReq, TxSignResp, TxoSynced},
    Commands,
};

use ledger_mob::{tx::TxConfig, Connect, DeviceHandle, LedgerProvider};
use ledger_mob_apdu::random::{RandomReq, RandomResp};

#[cfg(feature = "transport_hid")]
use ledger_mob::transport::TransportNativeHID;

#[cfg(feature = "transport_tcp")]
use ledger_mob::transport::{TcpOptions, TransportTcp};

mod helpers;
use helpers::*;

/// Ledger command line utility
#[derive(Clone, PartialEq, Debug, Parser)]
struct Options {
    /// Transport for ledger connection
    #[clap(subcommand)]
    transport: Transport,

    /// Enable verbose logging
    #[clap(long, default_value = "info")]
    log_level: LevelFilter,
}

#[derive(Clone, PartialEq, Debug, clap::ValueEnum)]
enum Format {
    Text,
    Json,
    Proto,
}

#[derive(Clone, PartialEq, Debug, Parser, Display)]
#[non_exhaustive]
enum Transport {
    /// USB HID
    Hid {
        #[clap(subcommand)]
        cmd: Actions,
    },
    /// Bluetooth Low Energy
    Ble,
    /// TCP (Speculos simulator)
    Tcp {
        //#[clap(flatten)]
        //opts: TcpOptions,
        #[clap(subcommand)]
        cmd: Actions,
    },
}

#[derive(Clone, PartialEq, Debug, Parser)]
#[non_exhaustive]
enum Actions {
    /// Fetch device info
    DeviceInfo,

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

    // Implement shared signer commands
    #[command(flatten)]
    Signer(Commands),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Options::parse();

    // Setup logging
    simplelog::SimpleLogger::init(args.log_level, simplelog::Config::default()).unwrap();

    // Connect to ledger device
    let p = LedgerProvider::new()?;

    debug!("Using transport: {:?}", args.transport);

    // Connect to transport and execute commands
    match args.transport {
        #[cfg(feature = "transport_tcp")]
        Transport::Tcp { cmd } => {
            let opts = TcpOptions::default();
            let t = Connect::<TransportTcp>::connect(&p, &opts).await?;

            execute(t, cmd).await?;
        }
        #[cfg(feature = "transport_hid")]
        Transport::Hid { cmd } => {
            let devices: Vec<_> = p.list_devices().collect();

            if devices.is_empty() {
                return Err(anyhow::anyhow!("No devices found"));
            }

            debug!("Found devices: {:04x?}", devices);

            let t = match Connect::<TransportNativeHID>::connect(&p, &devices[0]).await {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to connect to device: {:04x?}", devices[0]);
                    return Err(e.into());
                }
            };

            execute(t, cmd).await?;
        }
        _ => todo!("transport {} not available", args.transport),
    };

    Ok(())
}

/// Execute a command with the provided transport
async fn execute<T, E>(t: DeviceHandle<T>, cmd: Actions) -> anyhow::Result<()>
where
    T: Exchange<Error = E> + Sync + Send,
    E: Error + Sync + Send + 'static,
{
    use ledger_apdu::apdus::*;

    let mut buff = [0u8; 1024];

    debug!("Executing command: {:?}", cmd);

    match cmd {
        Actions::DeviceInfo => {
            let i = t
                .exchange::<DeviceInfo>(DeviceInfoGet {}, &mut buff)
                .await?;

            info!("device info: {:#?}", i);
        }
        Actions::AppInfo => {
            let i = t.exchange::<AppInfo>(AppInfoGet {}, &mut buff).await?;

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

            let r = t.exchange::<RandomResp>(RandomReq {}, &mut buff).await?;

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
                Commands::GetAccount { output, .. } => {
                    Commands::get_account(&a, account_index, output)?
                }
                Commands::SyncTxos { input, output, .. } => Commands::sync_txos(&a, input, output)?,
                Commands::SignTx { input, output, .. } => {
                    // Read in transaction file
                    debug!("Loading unsigned transaction from '{}'", input);
                    let req: TxSignReq = read_input(input).await?;

                    // Start device transaction
                    debug!("Starting transaction");
                    let signer = t
                        .transaction(TxConfig {
                            account_index,
                            num_memos: 0,
                            num_rings: req.rings.len(),
                        })
                        .await?;

                    // TODO: sign any memos

                    // Build the digest for ring signing
                    // TODO: this will move when TxSummary is complete
                    debug!("Building TX digest");
                    let (signing_data, _summary, _unblinding, digest) =
                        req.get_signing_data(&mut OsRng {}).unwrap();

                    // Set the message
                    debug!("Setting tx message");
                    signer.set_message(&digest.0).await?;

                    // Await user input
                    debug!("Waiting for user confirmation");
                    signer.await_approval(20).await?;

                    // Execute signing (signs rings etc.)
                    debug!("Executing signing operation");
                    let signature = signing_data
                        .sign(&req.rings, &signer, &mut OsRng {})
                        .map_err(|e| anyhow::anyhow!("Ring signing error: {:?}", e))?;

                    // Map key images to real inputs via public key
                    let mut txos = vec![];
                    for (i, r) in req.rings.iter().enumerate() {
                        let tx_out_public_key = match r {
                            InputRing::Signable(r) => r.members[r.real_input_index].public_key,
                            InputRing::Presigned(_) => panic!("Pre-signed rings unsupported"),
                        };

                        txos.push(TxoSynced {
                            tx_out_public_key: TxOutPublic::from(
                                RistrettoPublic::try_from(&tx_out_public_key).unwrap(),
                            ),
                            key_image: signature.ring_signatures[i].key_image,
                        });
                    }

                    // Build sign response
                    let resp = TxSignResp {
                        account_id: req.account_id,
                        tx: Tx {
                            prefix: req.tx_prefix.clone(),
                            signature,
                            fee_map_digest: vec![],
                        },
                        txos,
                    };

                    // Write output file
                    debug!("Writing signed transaction to '{}'", output);
                    write_output(output, &resp).await?;
                }
                _ => (),
            }
        }
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
