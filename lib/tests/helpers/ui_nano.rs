//! Button-driven ([BAGL][1]) UI driver for the nano devices.
//!
//! [1]: https://developers.ledger.com/docs/device-app/develop/ui/bagl

use std::{path::PathBuf, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use tracing::debug;

use ledger_sim::{Action, Button, EventFilter, GenericHandle, Handle};

use super::ui::{Screen, UiDriver};

/// Timeout awaiting an expected screen
const SCREEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between screen polls
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Upper bound on the pages traversed while navigating an approval flow.
///
/// Transaction approvals have a page per output and per total so the count
/// varies with the transaction, this exists to fail a broken flow rather than
/// page forever.
const MAX_PAGES: usize = 64;

// Text matched on each approval page.
//
// NOTE: these are matched as substrings of what speculos reports, which is not
// always what the device renders -- its BAGL text extraction drops the capital
// S of "Sync", reporting "Approve Sync" as "Approve ync".

/// Text matched on the wallet sync request page
#[allow(unused)]
pub const SYNC_INFO: &str = "Sync Wallet?";

/// Text matched on the wallet sync approval page (rendered "Approve Sync")
pub const SYNC_APPROVE: &str = "Approve";

/// Text matched on the wallet sync rejection page (rendered "Reject Sync")
#[allow(unused)]
pub const SYNC_REJECT: &str = "Reject";

/// Text matched on the first page of a transaction request
#[allow(unused)]
pub const TX_INFO: &str = "Transaction";

/// Text matched on the transaction approval page
pub const TX_APPROVE: &str = "Approve Transaction?";

/// Text matched on the transaction rejection page
#[allow(unused)]
pub const TX_REJECT: &str = "Reject Transaction?";

/// Button-driven ([BAGL][1]) [UiDriver] for the nano devices.
///
/// Approval flows on these devices are a list of pages walked with the right
/// button, ending in adjacent approve and reject pages selected with both
/// buttons. Navigation pages right until the expected page is displayed.
///
/// [1]: https://developers.ledger.com/docs/device-app/develop/ui/bagl
pub struct NanoUi<'a> {
    h: &'a GenericHandle,

    /// Where to write a screenshot of each page visited, if enabled
    screenshots: Option<PathBuf>,
}

impl<'a> NanoUi<'a> {
    /// Create a [NanoUi] driver for the provided simulator handle
    pub fn new(h: &'a GenericHandle) -> Self {
        Self {
            h,
            screenshots: None,
        }
    }

    /// Write a screenshot of each page visited to `<prefix>.<n>.png`
    pub fn with_screenshots(mut self, prefix: PathBuf) -> Self {
        self.screenshots = Some(prefix);
        self
    }

    /// Fetch the text currently displayed, waiting for a non-empty screen.
    async fn screen(&self) -> anyhow::Result<Screen> {
        let poll = async {
            loop {
                let events = self.h.events(EventFilter::CurrentScreen).await?;

                if !events.is_empty() {
                    return Ok(events.into_iter().map(|e| e.text).collect());
                }

                tokio::time::sleep(POLL_INTERVAL).await;
            }
        };

        match tokio::time::timeout(SCREEN_TIMEOUT, poll).await {
            Ok(v) => v,
            Err(_) => Err(anyhow!("timeout awaiting screen contents")),
        }
    }

    /// Press a button and wait for the display to settle on a different screen
    async fn press(&self, b: Button) -> anyhow::Result<Screen> {
        let before = self.h.events(EventFilter::CurrentScreen).await?;

        self.h.button(b, Action::PressAndRelease).await?;

        let poll = async {
            loop {
                let events = self.h.events(EventFilter::CurrentScreen).await?;

                if !events.is_empty() && events != before {
                    return Ok(events.into_iter().map(|e| e.text).collect());
                }

                tokio::time::sleep(POLL_INTERVAL).await;
            }
        };

        match tokio::time::timeout(SCREEN_TIMEOUT, poll).await {
            Ok(v) => v,
            Err(_) => Err(anyhow!("timeout awaiting screen change after {b} press")),
        }
    }

    /// Page right until a screen containing `text` is displayed, returning the
    /// text of every screen visited including the match.
    async fn navigate(&self, text: &str) -> anyhow::Result<Vec<Screen>> {
        let mut visited = Vec::new();
        let mut current = self.screen().await?;

        for _ in 0..MAX_PAGES {
            debug!("UI: {current:?}");

            self.capture(visited.len()).await?;
            visited.push(current.clone());

            if current.iter().any(|l| l.contains(text)) {
                return Ok(visited);
            }

            // A press that does not change the display means the last page has
            // been reached, which is a missing screen rather than a stuck one
            current = match self.press(Button::Right).await {
                Ok(v) => v,
                Err(_) => {
                    return Err(anyhow!(
                        "no screen containing {text:?}, {} pages visited: {visited:?}",
                        visited.len()
                    ))
                }
            };
        }

        Err(anyhow!(
            "no screen containing {text:?} within {MAX_PAGES} pages (last: {current:?})"
        ))
    }

    /// Select the currently displayed page
    async fn select(&self) -> anyhow::Result<()> {
        self.h.button(Button::Both, Action::PressAndRelease).await
    }

    /// Helper to navigate to `text` and select it
    async fn navigate_and_select(&self, text: &str) -> anyhow::Result<Vec<Screen>> {
        let visited = self.navigate(text).await?;

        // NOTE: the selection exits the approval UI, so no screen change is
        // awaited here -- what follows depends on the request being approved.
        self.select().await?;

        Ok(visited)
    }

    /// Write a screenshot of the current page where screenshots are enabled
    async fn capture(&self, n: usize) -> anyhow::Result<()> {
        let prefix = match &self.screenshots {
            Some(v) => v,
            None => return Ok(()),
        };

        if let Some(dir) = prefix.parent() {
            let _ = std::fs::create_dir_all(dir);
        }

        let name = prefix.file_name().and_then(|v| v.to_str()).unwrap_or("ui");
        let img = self.h.screenshot().await?;

        img.save(prefix.with_file_name(format!("{name}.{n}.png")))?;

        Ok(())
    }
}

#[async_trait]
impl UiDriver for NanoUi<'_> {
    async fn approve_sync(&self) -> anyhow::Result<Vec<Screen>> {
        debug!("UI: approve wallet sync");

        self.navigate_and_select(SYNC_APPROVE).await
    }

    async fn reject_sync(&self) -> anyhow::Result<Vec<Screen>> {
        debug!("UI: reject wallet sync");

        self.navigate_and_select(SYNC_REJECT).await
    }

    async fn approve_tx(&self) -> anyhow::Result<Vec<Screen>> {
        debug!("UI: approve transaction");

        self.navigate_and_select(TX_APPROVE).await
    }

    async fn reject_tx(&self) -> anyhow::Result<Vec<Screen>> {
        debug!("UI: reject transaction");

        self.navigate_and_select(TX_REJECT).await
    }
}
