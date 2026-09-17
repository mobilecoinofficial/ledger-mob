use bip39::{Language, Seed};

use ledger_mob_core::engine::Engine;

use mc_core::slip10::Mnemonic;

mod helpers;
use helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn key_image() -> anyhow::Result<()> {
    setup_logging();

    let mnemonic = Mnemonic::from_phrase(MNEMONIC, Language::English)?;
    let seed = Seed::new(&mnemonic, "");

    let e = TestEngine::new(Engine::new(TestDriver::new(seed), Default::default()));

    e.unlock();

    ledger_mob_tests::key_image::test(e, mnemonic)
        .await
        .unwrap();

    Ok(())
}
