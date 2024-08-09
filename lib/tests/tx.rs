use std::{path::PathBuf, time::Duration};

use log::{debug, info};

use bip39::{Language, Mnemonic, Seed};

use ledger_mob_tests::transaction::{test, TransactionExpectation, TRANSACTIONS};
use ledger_sim::*;

mod helpers;
use helpers::setup;

async fn tx<'a>(v: &TransactionExpectation<'a>, n: usize) -> anyhow::Result<()> {
    // Generate mnemonic
    // NOTE TX MNEMONIC MUST MATCH OBJECT
    let mnemonic = Mnemonic::from_phrase(v.mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Setup simulator
    let (d, s, t) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Run transaction signing test
    test(t, || approve_tx(&s, n, BUTTONS_BLIND), v).await?;

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

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "summary"), ignore = "requires summary feature to run")]
async fn tx3() -> anyhow::Result<()> {
    let v = &TRANSACTIONS[2];

    // Generate mnemonic
    // NOTE TX MNEMONIC MUST MATCH OBJECT
    let mnemonic = Mnemonic::from_phrase(v.mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Setup simulator
    let (d, s, t) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Run transaction signing test
    test(t, || approve_tx(&s, 3, BUTTONS_SUMMARY), v).await?;

    // Exit simulator
    d.exit(s).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "summary"), ignore = "requires summary feature to run")]
async fn tx4() -> anyhow::Result<()> {
    let v = &TRANSACTIONS[3];

    // Generate mnemonic
    // NOTE TX MNEMONIC MUST MATCH OBJECT
    let mnemonic = Mnemonic::from_phrase(v.mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Setup simulator
    let (d, s, t) = setup(Some(format!("hex:{}", hex::encode(&seed)))).await;

    // Run transaction signing test
    test(t, || approve_tx(&s, 3, BUTTONS_SUMMARY), v).await?;

    // Exit simulator
    d.exit(s).await?;

    Ok(())
}

const BUTTONS_BLIND: &[Button] = &[
    // Right button to move to warning screen
    Button::Right,
    // Right button to move to hash screen
    Button::Right,
    // Right button to move to allow screen
    Button::Right,
    // Both buttons to select allow
    Button::Both,
];

const BUTTONS_SUMMARY: &[Button] = &[
    // Right button to show balance
    Button::Right,
    // Right button to show send
    Button::Right,
    // Right button to show fee
    Button::Right,
    // Right button to show allow
    Button::Right,
    // Both buttons to select allow
    Button::Both,
];

/// Run transaction approval UI where required for tests
// TODO: this will change with TxSummary support
#[allow(unused)]
pub async fn approve_tx(h: &GenericHandle, n: usize, buttons: &[Button]) {
    debug!("UI: Approve");

    // Setup output directory
    let out_dir = PathBuf::from("../target/ui");
    let _ = std::fs::create_dir_all(&out_dir);

    let mut i = 0;

    // Take initial screenshot
    let img = h.screenshot().await.unwrap();
    img.save(out_dir.join(format!("tx-{n}.{i}.png"))).unwrap();
    i += 1;

    for b in buttons {
        // Apply button press
        h.button(*b, Action::PressAndRelease).await.unwrap();

        // Wait a moment
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Screenshot after each button press
        let img = h.screenshot().await.unwrap();
        img.save(out_dir.join(format!("tx-{n}.{i}.png"))).unwrap();

        i += 1;
    }
}
