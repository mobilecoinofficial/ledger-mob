use ledger_mob_tests::ident::VECTORS;
use ledger_sim::*;

mod helpers;
use helpers::{approve_ident, approve_ident_capture, reject_ident_capture, setup};

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "ident"), ignore = "requires ident feature to run")]
async fn mob_ident_approve() -> anyhow::Result<()> {
    for (i, v) in VECTORS.iter().enumerate() {
        // Setup simulator with provided seed
        let seed = v.seed();
        let (d, s, t, m) = setup(Some(format!("hex:{}", hex::encode(seed)))).await;

        let name = format!("ident-{i}");
        ledger_mob_tests::ident::test_approve(t, || approve_ident_capture(m, &s, &name), v)
            .await
            .expect("Test run failed");

        // Exit simulator
        d.exit(s).await.expect("Target exit failed");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "ident"), ignore = "requires ident feature to run")]
async fn mob_ident_reject() -> anyhow::Result<()> {
    for (i, v) in VECTORS.iter().enumerate() {
        // Setup simulator with provided seed
        let seed = v.seed();
        let (d, s, t, m) = setup(Some(format!("hex:{}", hex::encode(seed)))).await;

        let name = format!("ident-{i}-reject");
        ledger_mob_tests::ident::test_reject(t, || reject_ident_capture(m, &s, &name), v)
            .await
            .expect("Test run failed");

        // Exit simulator
        d.exit(s).await.expect("Target exit failed");
    }

    Ok(())
}

/// Identity request via `DeviceHandle::identity`, which polls for approval
/// while the (blocking, on touch devices) review is displayed
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "ident"), ignore = "requires ident feature to run")]
async fn mob_ident_handle() -> anyhow::Result<()> {
    let v = &VECTORS[0];

    // Setup simulator with provided seed
    let seed = v.seed();
    let (d, s, t, m) = setup(Some(format!("hex:{}", hex::encode(seed)))).await;

    ledger_mob_tests::ident::test_handle(t, || approve_ident(m, &s), v)
        .await
        .expect("Test run failed");

    // Exit simulator
    d.exit(s).await.expect("Target exit failed");

    Ok(())
}
