//! UI drivers for simulator integration tests.
//!
//! Tests drive the on-device approval flows through the speculos HTTP API.
//! Rather than replaying a fixed sequence of button presses, drivers read the
//! displayed text back via the `/events` API and navigate until the expected
//! screen is shown, so a test fails where the UI diverges instead of silently
//! pressing its way through the wrong pages.
//!
//! Only the button-driven (BAGL) nano devices are implemented, see
//! [NanoUi][super::ui_nano::NanoUi].

use std::path::PathBuf;

use async_trait::async_trait;

use ledger_sim::{GenericHandle, Model};

use super::ui_nano::NanoUi;

/// The text displayed on one screen, one entry per rendered string
pub type Screen = Vec<String>;

/// UI operations required by the integration tests, implemented per UI stack
/// so tests are not written against one device's input mechanism.
#[allow(unused)]
#[async_trait]
pub trait UiDriver {
    /// Approve a wallet sync (unlock) request, returning the screens visited
    async fn approve_sync(&self) -> anyhow::Result<Vec<Screen>>;

    /// Reject a wallet sync (unlock) request, returning the screens visited
    async fn reject_sync(&self) -> anyhow::Result<Vec<Screen>>;

    /// Approve a transaction request, returning the screens visited.
    ///
    /// This covers both the blind and summary approvals, which differ in the
    /// pages shown between the request and approval pages.
    async fn approve_tx(&self) -> anyhow::Result<Vec<Screen>>;

    /// Reject a transaction request, returning the screens visited
    async fn reject_tx(&self) -> anyhow::Result<Vec<Screen>>;
}

/// Fetch the [UiDriver] for a given simulator [Model]
pub fn ui_for(model: Model, h: &GenericHandle) -> Box<dyn UiDriver + Send + Sync + '_> {
    match model {
        Model::NanoS | Model::NanoSP | Model::NanoX => Box::new(NanoUi::new(h)),
        // Touch (NBGL) approval pages are not yet implemented in the firmware,
        // see `fw/src/ui/touch`
        m => unimplemented!("no UI driver for model: {m}"),
    }
}

/// Fetch the [UiDriver] for a given simulator [Model], writing a screenshot of
/// each page visited to `<prefix>.<n>.png`
pub fn ui_for_with_screenshots(
    model: Model,
    h: &GenericHandle,
    prefix: PathBuf,
) -> Box<dyn UiDriver + Send + Sync + '_> {
    match model {
        Model::NanoS | Model::NanoSP | Model::NanoX => {
            Box::new(NanoUi::new(h).with_screenshots(prefix))
        }
        m => unimplemented!("no UI driver for model: {m}"),
    }
}
