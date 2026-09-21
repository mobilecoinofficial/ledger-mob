use ledger_mob_tests::ident::VECTORS;
use ledger_sim::*;

mod helpers;
use helpers::{approve_ident, model, setup, ModelUiExt};

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "ident"), ignore = "requires ident feature to run")]
async fn mob_ident() -> anyhow::Result<()> {
    let m = model();
    if m.is_touch() {
        println!("skipping: identity approval UI not yet implemented for {m}");
        return Ok(());
    }

    for v in VECTORS {
        // Setup simulator with provided seed
        let seed = v.seed();
        let (d, s, t, m) = setup(Some(format!("hex:{}", hex::encode(seed)))).await;

        ledger_mob_tests::ident::test(t, || approve_ident(m, &s), v)
            .await
            .expect("Test run failed");

        // Exit simulator
        d.exit(s).await.expect("Target exit failed");
    }

    Ok(())
}
