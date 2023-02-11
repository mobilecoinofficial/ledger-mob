use bip39::{Language, Mnemonic, Seed};
use curve25519_dalek::scalar::Scalar;
use ledger_transport_tcp::TransportTcp;
use log::info;
use serde::{Deserialize, Serialize};

use mc_core::keys::*;

use ledger_sim::*;
use ledger_transport::Exchange;

use ledger_mob_apdu::wallet_keys::{WalletKeyReq, WalletKeyResp};
use ledger_mob_tests::wallet;

mod helpers;
use helpers::{approve, setup};

const MNEMONIC: &str = "duck deal pretty pen thunder economy wide common goose fit engine main aisle curtain choose cube claim snake enroll detect brief history float unit";

#[tokio::test(flavor = "multi_thread")]
async fn mob_wallet_keys() -> anyhow::Result<()> {
    // Generate random mnemonic
    let mnemonic = Mnemonic::from_phrase(MNEMONIC, Language::English)?;
    let seed = Seed::new(&mnemonic, "");

    info!("using mnemonic: '{}'", mnemonic.phrase());
    info!("seed: '{}'", base64::encode(&seed));

    // Setup simulator
    let (d, s, t) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Test wallet key generation
    wallet::test(t, || approve(&s), mnemonic).await?;

    // Exit simulator
    d.exit(s).await?;

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Wallet {
    pub phrase: String,
    pub account_index: u32,
    pub view_hex: String,
    pub spend_hex: String,
}

impl Wallet {
    pub fn view_private(&self) -> RootViewPrivate {
        let mut buff = [0u8; 64];
        hex::decode_to_slice(&self.view_hex, &mut buff).unwrap();

        let s = Scalar::from_bytes_mod_order_wide(&buff);
        RootViewPrivate::from(s)
    }

    pub fn spend_private(&self) -> RootSpendPrivate {
        let mut buff = [0u8; 64];
        hex::decode_to_slice(&self.spend_hex, &mut buff).unwrap();

        let s = Scalar::from_bytes_mod_order_wide(&buff);
        RootSpendPrivate::from(s)
    }

    pub fn spend_public(&self) -> RootSpendPublic {
        self.spend_private().into()
    }
}

/// wallet test vectors from mc-account-keys-slip10
const TEST_WALLET_SRC: &str = include_str!("wallet_keys.toml");

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct TestConfig {
    pub wallets: Vec<Wallet>,
}

lazy_static::lazy_static! {
    static ref TEST_WALLETS: Vec<Wallet> = toml::from_str::<TestConfig>(TEST_WALLET_SRC).map(|v| v.wallets ).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "full run takes a couple of minutes, CI only"]
async fn mob_mnemonic_derive_full() -> anyhow::Result<()> {
    mob_mnemonic_derive(&TEST_WALLETS).await
}

#[tokio::test(flavor = "multi_thread")]
async fn mob_mnemonic_derive_partial() -> anyhow::Result<()> {
    mob_mnemonic_derive(&TEST_WALLETS[..4]).await
}

async fn get_account_keys(t: &TransportTcp, index: u32) -> anyhow::Result<WalletKeyResp> {
    let mut buff = [0u8; 256];

    let r = t
        .exchange::<WalletKeyResp>(WalletKeyReq::new(index), &mut buff)
        .await?;

    Ok(r)
}

async fn mob_mnemonic_derive(wallets: &[Wallet]) -> anyhow::Result<()> {
    for w in wallets {
        // Load in mnemonic
        let mnemonic = Mnemonic::from_phrase(&w.phrase, Language::English)?;
        let seed = Seed::new(&mnemonic, "");
        info!("using mnemonic: '{}'", mnemonic.phrase());
        info!("seed: '{}'", base64::encode(&seed));

        // Setup simulator
        let (d, s, t) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

        // Fetch wallet keys from device
        let r = match get_account_keys(&t, w.account_index).await {
            Ok(v) => v,
            // App requires approval
            Err(_) => {
                // Set approved
                approve(&s).await;

                // Retry request (for some reason the simulator fails the first
                // time this is re-requested, though the device does not..?)
                let _ = get_account_keys(&t, w.account_index).await;

                get_account_keys(&t, w.account_index).await?
            }
        };

        // Check wallet keys match expectation
        assert_eq!(r.spend_public, w.spend_public(),);
        assert_eq!(r.view_private, w.view_private(),);

        d.exit(s).await?;
    }

    Ok(())
}
