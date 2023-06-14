use std::time::Duration;

use ledger_mob_tests::ident::VECTORS;
use ledger_sim::*;

mod helpers;
use helpers::setup;

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(feature = "ident"), ignore = "requires ident feature to run")]
async fn mob_ident() -> anyhow::Result<()> {
    for v in VECTORS {
        // Setup simulator with provided seed
        let seed = v.seed();
        let (d, s, t) = setup(Some(format!("hex:{}", hex::encode(seed)))).await;

        ledger_mob_tests::ident::test(t, || approve_ident(&s), v)
            .await
            .expect("Test run failed");

        // Exit simulator
        d.exit(s).await.expect("Target exit failed");
    }

    Ok(())
}

/// Run transaction approval UI where required for tests
// TODO: this will change with TxSummary support
#[allow(unused)]
pub async fn approve_ident(h: &GenericHandle) {
    log::debug!("UI: Approve ident");

    let buttons = &[
        // Right button to move to URI screen
        Button::Right,
        // Right button to move to challenge screen
        Button::Right,
        // Right button to move to allow screen
        Button::Right,
        // Both buttons to approve ident
        Button::Both,
    ];

    for b in buttons {
        // Press button
        h.button(*b, Action::PressAndRelease).await.unwrap();
        // Wait a moment for emulator to catch up
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
