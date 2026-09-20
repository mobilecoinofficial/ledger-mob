use tracing::info;

use ledger_sim::Driver;

use bip39::{Language, Mnemonic, Seed};

use ledger_mob_tests::transaction::{test, test_reject, TransactionExpectation, TRANSACTIONS};

mod helpers;
use helpers::{approve_tx_capture, model, reject_tx_capture, setup, ModelUiExt};

async fn tx<'a>(v: &TransactionExpectation<'a>, n: usize) -> anyhow::Result<()> {
    // Generate mnemonic
    // NOTE TX MNEMONIC MUST MATCH OBJECT
    let mnemonic = Mnemonic::from_phrase(v.mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Setup simulator
    let (d, s, t, m) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Run transaction signing test
    let name = format!("tx-{n}");
    test(t, || approve_tx_capture(m, &s, &name), v).await?;

    // Exit simulator
    d.exit(s).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tx1() -> anyhow::Result<()> {
    tx(&TRANSACTIONS[0], 1).await
}

#[tokio::test(flavor = "multi_thread")]
async fn tx2() -> anyhow::Result<()> {
    tx(&TRANSACTIONS[1], 2).await
}

/// [tx], rejecting the transaction on the device instead of approving it.
///
/// Only the blind vectors are covered here, the summary approval UI has its
/// own reject page and is not yet implemented on the touch devices.
async fn tx_reject<'a>(v: &TransactionExpectation<'a>, n: usize) -> anyhow::Result<()> {
    // Generate mnemonic
    // NOTE TX MNEMONIC MUST MATCH OBJECT
    let mnemonic = Mnemonic::from_phrase(v.mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Setup simulator
    let (d, s, t, m) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Run transaction rejection test
    let name = format!("tx-{n}-reject");
    test_reject(t, || reject_tx_capture(m, &s, &name), v).await?;

    // Exit simulator
    d.exit(s).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tx1_reject() -> anyhow::Result<()> {
    tx_reject(&TRANSACTIONS[0], 1).await
}

#[tokio::test(flavor = "multi_thread")]
async fn tx2_reject() -> anyhow::Result<()> {
    tx_reject(&TRANSACTIONS[1], 2).await
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "summary"), ignore = "requires summary feature to run")]
async fn tx3() -> anyhow::Result<()> {
    let v = &TRANSACTIONS[2];

    let m = model();
    if m.is_touch() {
        println!("skipping: transaction summary approval UI not yet implemented for {m}");
        return Ok(());
    }

    // Generate mnemonic
    // NOTE TX MNEMONIC MUST MATCH OBJECT
    let mnemonic = Mnemonic::from_phrase(v.mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Setup simulator
    let (d, s, t, m) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Run transaction signing test
    test(t, || approve_tx_capture(m, &s, "tx-3"), v).await?;

    // Exit simulator
    d.exit(s).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "summary"), ignore = "requires summary feature to run")]
async fn tx4() -> anyhow::Result<()> {
    let v = &TRANSACTIONS[3];

    let m = model();
    if m.is_touch() {
        println!("skipping: transaction summary approval UI not yet implemented for {m}");
        return Ok(());
    }

    // Generate mnemonic
    // NOTE TX MNEMONIC MUST MATCH OBJECT
    let mnemonic = Mnemonic::from_phrase(v.mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Setup simulator
    let (d, s, t, m) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Run transaction signing test
    test(t, || approve_tx_capture(m, &s, "tx-4"), v).await?;

    // Exit simulator
    d.exit(s).await?;

    Ok(())
}
