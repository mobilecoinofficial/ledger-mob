use bip39::{Language, Mnemonic, Seed};

use ledger_mob_core::engine::Engine;
use ledger_mob_tests::transaction::{test, TRANSACTIONS};

mod helpers;
use helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn tx1() -> anyhow::Result<()> {
    setup_logging();

    let mnemonic = Mnemonic::from_phrase(TRANSACTIONS[0].mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");

    let e = TestEngine::new(Engine::new(TestDriver::new(seed)));

    e.unlock();

    test(e.clone(), || approve_tx(&e), &TRANSACTIONS[0])
        .await
        .unwrap();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tx2() -> anyhow::Result<()> {
    setup_logging();

    let mnemonic = Mnemonic::from_phrase(TRANSACTIONS[1].mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");

    let e = TestEngine::new(Engine::new(TestDriver::new(seed)));

    e.unlock();

    test(e.clone(), || approve_tx(&e), &TRANSACTIONS[1])
        .await
        .unwrap();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tx3() -> anyhow::Result<()> {
    setup_logging();

    let mnemonic = Mnemonic::from_phrase(TRANSACTIONS[2].mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");

    let e = TestEngine::new(Engine::new(TestDriver::new(seed)));

    e.unlock();

    test(e.clone(), || approve_tx(&e), &TRANSACTIONS[2])
        .await
        .unwrap();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tx4() -> anyhow::Result<()> {
    setup_logging();

    let mnemonic = Mnemonic::from_phrase(TRANSACTIONS[3].mnemonic, Language::English)?;
    let seed = Seed::new(&mnemonic, "");

    let e = TestEngine::new(Engine::new(TestDriver::new(seed)));

    e.unlock();

    test(e.clone(), || approve_tx(&e), &TRANSACTIONS[3])
        .await
        .unwrap();

    Ok(())
}
