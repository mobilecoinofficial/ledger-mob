use log::info;

use base64::{engine::general_purpose::STANDARD, Engine};
use bip39::{Language, Mnemonic, Seed};

use ledger_mob_tests::subaddress;
use ledger_sim::*;

mod helpers;
use helpers::{approve_wallet_sync, setup};

const MNEMONIC: &str = "duck deal pretty pen thunder economy wide common goose fit engine main aisle curtain choose cube claim snake enroll detect brief history float unit";

#[tokio::test(flavor = "multi_thread")]
async fn mob_default_subaddress() -> anyhow::Result<()> {
    // Generate random mnemonic
    let mnemonic = Mnemonic::from_phrase(MNEMONIC, Language::English)?;
    let seed = Seed::new(&mnemonic, "");

    info!("using mnemonic: '{}'", mnemonic.phrase());
    info!("seed: '{}'", STANDARD.encode(&seed));

    // Setup simulator
    let (d, s, t) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Run default subaddress test
    subaddress::test(t, || approve_wallet_sync(&s), mnemonic, 16).await?;

    // Exit simulator
    d.exit(s).await?;

    Ok(())
}
