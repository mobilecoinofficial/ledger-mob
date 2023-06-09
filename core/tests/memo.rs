use bip39::{Language, Seed};

use ledger_mob_core::engine::{Engine, RING_SIZE};

use mc_core::slip10::Mnemonic;

mod helpers;
use helpers::*;

#[tokio::test(flavor = "multi_thread")]
async fn memo_sign() -> anyhow::Result<()> {
    let _ = simplelog::SimpleLogger::init(log::LevelFilter::Debug, Default::default());

    let mnemonic = Mnemonic::from_phrase(MNEMONIC, Language::English)?;
    let seed = Seed::new(&mnemonic, "");

    let e = TestEngine::new(Engine::new(TestDriver::new(seed)));

    ledger_mob_tests::memo::hmac(e, mnemonic, RING_SIZE)
        .await
        .unwrap();

    Ok(())
}
