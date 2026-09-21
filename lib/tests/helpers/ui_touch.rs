//! Touchscreen ([NBGL][1]) UI driver for the stax, flex and apex devices.
//!
//! Only the wallet sync approval is implemented, matching the firmware -- the
//! transaction and identity pages in `fw/src/ui/touch` are still stubs, so the
//! corresponding methods here fail rather than pretending to drive them.
//!
//! [1]: https://developers.ledger.com/docs/device-app/develop/ui/nbgl

use std::path::PathBuf;

use anyhow::anyhow;
use async_trait::async_trait;
use tracing::debug;

use ledger_sim::{Event, EventFilter, GenericHandle, Handle, Model};

use super::ui::{capture, Screen, UiDriver, POLL_INTERVAL, SCREEN_TIMEOUT};

/// Text shown on the wallet sync request page
pub const SYNC_INFO: &str = "Sync Wallet?";

/// Label of the wallet sync confirmation button
pub const SYNC_APPROVE: &str = "Sync";

/// Label of the wallet sync rejection button
#[allow(unused)]
pub const SYNC_REJECT: &str = "Reject";

/// Text shown on the home page, displayed once a request page is dismissed
pub const HOME: &str = "MobileCoin";

/// Touchscreen ([NBGL][1]) [UiDriver].
///
/// Approval pages here are not a sequence to page through as on the nano
/// devices, they are a single page with buttons. Text events carry the pixel
/// box of the drawn label, so a button is located by its label and tapped at
/// the centre of that box.
///
/// [1]: https://developers.ledger.com/docs/device-app/develop/ui/nbgl
pub struct TouchUi<'a> {
    model: Model,

    h: &'a GenericHandle,

    /// Where to write a screenshot of each page visited, if enabled
    screenshots: Option<PathBuf>,
}

impl<'a> TouchUi<'a> {
    /// Create a [TouchUi] driver for the provided simulator handle, optionally
    /// writing a screenshot of each page visited to `<prefix>.<n>.png`
    pub fn new(model: Model, h: &'a GenericHandle, screenshots: Option<PathBuf>) -> Self {
        Self {
            model,
            h,
            screenshots,
        }
    }

    /// Await a screen containing `text`, returning the events that make it up.
    ///
    /// NOTE: speculos only resets the current screen on a full-screen redraw,
    /// so this matches on the expected text rather than on the screen changing.
    async fn wait_for(&self, text: &str) -> anyhow::Result<Vec<Event>> {
        let poll = async {
            loop {
                let events = self.h.events(EventFilter::CurrentScreen).await?;

                if events.iter().any(|e| e.text.contains(text)) {
                    return Ok(events);
                }

                tokio::time::sleep(POLL_INTERVAL).await;
            }
        };

        match tokio::time::timeout(SCREEN_TIMEOUT, poll).await {
            Ok(v) => v,
            Err(_) => {
                let shown = self.h.events(EventFilter::CurrentScreen).await?;
                let shown: Screen = shown.into_iter().map(|e| e.text).collect();

                Err(anyhow!(
                    "timeout awaiting screen containing {text:?} on {} (shown: {shown:?})",
                    self.model
                ))
            }
        }
    }

    /// Tap the centre of the label exactly matching `label` among `events`.
    ///
    /// The match is exact so that a button label is not confused with the page
    /// text containing it, e.g. the "Sync" button against "Sync Wallet?".
    async fn tap_label(&self, events: &[Event], label: &str) -> anyhow::Result<()> {
        let e = events.iter().find(|e| e.text.trim() == label);

        let e = match e {
            Some(v) => v,
            None => {
                let shown: Screen = events.iter().map(|e| e.text.clone()).collect();

                return Err(anyhow!(
                    "no {label:?} button on {} (shown: {shown:?})",
                    self.model
                ));
            }
        };

        // Events carry the pixel box of the drawn text, tap its centre
        let (x, y) = (e.x + e.w / 2, e.y + e.h / 2);

        debug!("UI: tapping {label:?} at ({x}, {y})");

        self.h.tap(x as u16, y as u16).await
    }

    /// Await the sync request page, tap `label`, and wait for the home page
    /// so the caller only proceeds once the choice has been dismissed
    async fn choose_sync(&self, label: &str) -> anyhow::Result<Vec<Screen>> {
        let events = self.wait_for(SYNC_INFO).await?;

        let page: Screen = events.iter().map(|e| e.text.clone()).collect();
        debug!("UI: {page:?}");

        capture(self.h, &self.screenshots, 0).await?;

        self.tap_label(&events, label).await?;

        self.wait_for(HOME).await?;

        capture(self.h, &self.screenshots, 1).await?;

        Ok(vec![page])
    }

    /// Error for the approval pages the touch firmware has yet to implement
    fn unimplemented(&self, flow: &str) -> anyhow::Error {
        anyhow!(
            "{flow} UI is not implemented for {} (see fw/src/ui/touch)",
            self.model
        )
    }
}

#[async_trait]
impl UiDriver for TouchUi<'_> {
    async fn approve_sync(&self) -> anyhow::Result<Vec<Screen>> {
        debug!("UI: approve wallet sync");

        self.choose_sync(SYNC_APPROVE).await
    }

    async fn reject_sync(&self) -> anyhow::Result<Vec<Screen>> {
        debug!("UI: reject wallet sync");

        self.choose_sync(SYNC_REJECT).await
    }

    async fn approve_tx(&self) -> anyhow::Result<Vec<Screen>> {
        Err(self.unimplemented("transaction approval"))
    }

    async fn reject_tx(&self) -> anyhow::Result<Vec<Screen>> {
        Err(self.unimplemented("transaction rejection"))
    }

    async fn approve_ident(&self) -> anyhow::Result<Vec<Screen>> {
        Err(self.unimplemented("identity approval"))
    }
}
