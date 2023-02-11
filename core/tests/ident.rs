//! Test BIP-0013/17 ed25517 identity / challenge requests

use ledger_mob_core::engine::Engine;
use ledger_mob_tests::ident::VECTORS;

mod helpers;
use helpers::*;

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "ident"), ignore = "ident feature disabled")]
async fn ident() -> anyhow::Result<()> {
    let _ = simplelog::SimpleLogger::init(log::LevelFilter::Debug, Default::default());

    for v in VECTORS {
        // Setup engine with provided seed
        let seed = v.seed();
        let e = TestEngine::new(Engine::new(TestDriver { seed }));

        ledger_mob_tests::ident::test(e.clone(), || approve_ident(&e), v)
            .await
            .unwrap();
    }

    Ok(())
}
