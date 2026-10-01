//! UI drivers for simulator integration tests.
//!
//! Tests drive the on-device approval flows through the speculos HTTP API.
//!
//! Two UI stacks are implemented:
//! - [NanoUi][super::ui_nano::NanoUi] for button driven (BAGL) nano devices
//! - [TouchUi][super::ui_touch::TouchUi] for touchscreen (NBGL) devices.

use std::{path::PathBuf, time::Duration};

use async_trait::async_trait;

use ledger_sim::{GenericHandle, Handle, Model};

use super::{ui_nano::NanoUi, ui_touch::TouchUi};

/// Timeout awaiting an expected screen
pub const SCREEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between screen polls
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

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

    /// Approve an identity (challenge signing) request, returning the screens
    /// visited
    async fn approve_ident(&self) -> anyhow::Result<Vec<Screen>>;
}

/// Extension trait for the [Model] type to provide test UI helpers.
pub trait ModelUiExt {
    fn is_touch(&self) -> bool;

    fn ui_for<'a>(&self, h: &'a GenericHandle) -> Box<dyn UiDriver + Send + Sync + 'a>;

    fn ui_for_with_screenshots<'a>(
        &self,
        h: &'a GenericHandle,
        prefix: PathBuf,
    ) -> Box<dyn UiDriver + Send + Sync + 'a>;
}

impl ModelUiExt for Model {
    fn is_touch(&self) -> bool {
        matches!(self, Model::Stax | Model::Flex | Model::NanoGen5)
    }

    fn ui_for<'a>(&self, h: &'a GenericHandle) -> Box<dyn UiDriver + Send + Sync + 'a> {
        ui_inner(*self, h, None)
    }

    fn ui_for_with_screenshots<'a>(
        &self,
        h: &'a GenericHandle,
        prefix: PathBuf,
    ) -> Box<dyn UiDriver + Send + Sync + 'a> {
        ui_inner(*self, h, Some(prefix))
    }
}

fn ui_inner<'a>(
    model: Model,
    h: &'a GenericHandle,
    prefix: Option<PathBuf>,
) -> Box<dyn UiDriver + Send + Sync + 'a> {
    match model {
        Model::NanoS | Model::NanoSP | Model::NanoX => Box::new(NanoUi::new(h, prefix)),
        Model::Stax | Model::Flex | Model::NanoGen5 => Box::new(TouchUi::new(model, h, prefix)),
    }
}

/// Write a screenshot of the current page to `<prefix>.<n>.png` where a prefix
/// is configured, shared by the [UiDriver] implementations.
pub async fn capture(h: &GenericHandle, prefix: &Option<PathBuf>, n: usize) -> anyhow::Result<()> {
    let prefix = match prefix {
        Some(v) => v,
        None => return Ok(()),
    };

    if let Some(dir) = prefix.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    let name = prefix.file_name().and_then(|v| v.to_str()).unwrap_or("ui");
    let img = h.screenshot().await?;

    img.save(prefix.with_file_name(format!("{name}.{n}.png")))?;

    Ok(())
}
