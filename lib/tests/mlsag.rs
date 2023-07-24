use log::info;

use bip39::{Language, Mnemonic, Seed};

use ledger_mob_tests::mlsag::{self};
use ledger_sim::*;

mod helpers;
use helpers::{approve_tx_blind, setup};

const MNEMONIC: &str = "duck deal pretty pen thunder economy wide common goose fit engine main aisle curtain choose cube claim snake enroll detect brief history float unit";

#[tokio::test(flavor = "multi_thread")]
async fn mob_mlsag() -> anyhow::Result<()> {
    // Generate mnemonic
    let mnemonic = Mnemonic::from_phrase(MNEMONIC, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Setup simulator
    let (d, s, t) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Run ring signature test
    mlsag::test(t, || approve_tx_blind(&s), mnemonic, 11).await?;

    // Exit simulator
    d.exit(s).await?;

    Ok(())
}
