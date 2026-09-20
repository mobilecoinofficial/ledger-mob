//! Touchscreen ([NBGL][1]) UI driver for the stax, flex and apex devices.
//!
//! [1]: https://developers.ledger.com/docs/device-app/develop/ui/nbgl

use std::{path::PathBuf, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use tracing::debug;

use ledger_sim::{Action, Event, EventFilter, GenericHandle, Handle, Model};

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

// Text matched on the blind transaction approval pages.
//
// The app supplies the review titles (see `fw/src/ui/touch/tx_blind_request.rs`),
// everything else is drawn by the SDK's `nbgl_useCaseReviewBlindSigning` flow and
// matched against the strings in `lib_nbgl/src/nbgl_use_case.c`.

/// Text shown on the blind signing warning, displayed ahead of the review itself
pub const TX_BLIND_WARN: &str = "Blind signing ahead";

/// Label of the button that continues from the warning into the review
pub const TX_BLIND_CONTINUE: &str = "Continue anyway";

/// Label of the button that abandons the review from the warning page.
///
/// This rejects immediately, without the confirmation [TX_REJECT] goes through.
#[allow(unused)]
pub const TX_BLIND_BACK: &str = "Back to safety";

/// Label of the long press button on the last review page.
///
/// NOTE: pages are located by button label rather than by title, as NBGL wraps
/// a title too long for the screen and speculos reports each line as its own
/// event -- the last review page arrives as `["Sign MobileCoin ",
/// "transaction?", "Reject", "3 of 3", "Hold to sign"]`, which no substring
/// match against the title can find.
pub const TX_HOLD: &str = "Hold to sign";

/// Label of the reject control in the review footer
pub const TX_REJECT: &str = "Reject";

/// Label of the button confirming rejection on the confirmation page, which is
/// titled "Reject transaction?"
pub const TX_REJECT_YES: &str = "Yes, reject";

/// Status shown once a transaction has been signed
pub const TX_SIGNED: &str = "Transaction signed";

/// Status shown once a transaction has been rejected
pub const TX_REJECTED: &str = "Transaction rejected";

/// How long a long press button must be held for NBGL to accept it.
///
/// `LONG_TOUCH_DURATION` in the SDK (`lib_nbgl/include/nbgl_touch.h`) is 3000ms,
/// held a little longer here to absorb simulator jitter.
const LONG_PRESS: Duration = Duration::from_millis(3500);

/// Upper bound on the pages swiped through while navigating a review, so a
/// broken flow fails rather than swiping forever.
const MAX_PAGES: usize = 16;

/// Touchscreen ([NBGL][1]) [UiDriver].
///
/// Approval pages here are not a sequence to page through as on the nano
/// devices, they are a single page with buttons. Text events carry the pixel
/// box of the drawn label, so a button is located by its label and tapped at
/// the centre of that box.
///
/// Transaction reviews do span several pages, advanced by swiping or by a button press.
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

    /// Screen size in pixels, from `SCREEN_WIDTH` / `SCREEN_HEIGHT` in the SDK
    /// (`lib_nbgl/include/nbgl_types.h`). Used to place swipes, which are not
    /// anchored to any drawn text.
    fn screen_size(&self) -> (u16, u16) {
        match self.model {
            Model::Flex => (480, 600),
            Model::NanoGen5 => (300, 400),
            _ => (400, 672),
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
            Err(_) => Err(self.missing(text).await),
        }
    }

    /// Locate the centre of the label exactly matching `label` among `events`.
    ///
    /// The match is exact so that a button label is not confused with the page
    /// text containing it, e.g. the "Sync" button against "Sync Wallet?".
    fn label_centre(&self, events: &[Event], label: &str) -> anyhow::Result<(u16, u16)> {
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

        // Events carry the pixel box of the drawn text, aim for its centre
        Ok(((e.x + e.w / 2) as u16, (e.y + e.h / 2) as u16))
    }

    /// Tap the centre of the label exactly matching `label` among `events`.
    async fn tap_label(&self, events: &[Event], label: &str) -> anyhow::Result<()> {
        let (x, y) = self.label_centre(events, label)?;

        debug!("UI: tapping {label:?} at ({x}, {y})");

        self.h.tap(x, y).await
    }

    /// Hold the long press button labelled `label` for [LONG_PRESS].
    ///
    /// NBGL only fires the confirmation once a touch has been held for
    /// `LONG_TOUCH_DURATION`, so this cannot be a [tap][Self::tap_label].
    async fn hold_label(&self, events: &[Event], label: &str) -> anyhow::Result<()> {
        let (x, y) = self.label_centre(events, label)?;

        debug!("UI: holding {label:?} at ({x}, {y})");

        self.h.touch(x, y, Action::Press).await?;
        tokio::time::sleep(LONG_PRESS).await;
        self.h.touch(x, y, Action::Release).await
    }

    /// Swipe right to left across the middle of the screen, advancing a review
    /// to its next page
    async fn swipe_next(&self) -> anyhow::Result<()> {
        let (w, h) = self.screen_size();
        let y = h / 2;

        debug!("UI: swiping to next page");

        self.h.swipe((w * 3 / 4, y), (w / 4, y)).await
    }

    /// Record the current page in `visited`, capturing a screenshot of it where
    /// screenshots are enabled
    async fn record(&self, events: &[Event], visited: &mut Vec<Screen>) -> anyhow::Result<()> {
        let page: Screen = events.iter().map(|e| e.text.clone()).collect();
        debug!("UI: {page:?}");

        capture(self.h, &self.screenshots, visited.len()).await?;
        visited.push(page);

        Ok(())
    }

    /// Swipe forward until a page containing `text` is displayed, recording
    /// every page visited on the way.
    ///
    /// This is the touch counterpart to [NanoUi::navigate][super::ui_nano],
    /// where forward navigation is a swipe rather than a right button press.
    async fn navigate(&self, text: &str, visited: &mut Vec<Screen>) -> anyhow::Result<Vec<Event>> {
        for _ in 0..MAX_PAGES {
            let events = self.h.events(EventFilter::CurrentScreen).await?;

            if events.iter().any(|e| e.text.contains(text)) {
                return Ok(events);
            }

            if !events.is_empty() {
                self.record(&events, visited).await?;
            }

            self.swipe_next().await?;

            // Give the page a moment to redraw before looking again
            tokio::time::sleep(POLL_INTERVAL).await;
        }

        Err(self.missing(text).await)
    }

    /// Error reporting what is on screen, for a page that never turned up
    async fn missing(&self, text: &str) -> anyhow::Error {
        let shown = match self.h.events(EventFilter::CurrentScreen).await {
            Ok(v) => v.into_iter().map(|e| e.text).collect::<Screen>(),
            Err(e) => return e,
        };

        anyhow!(
            "timeout awaiting screen containing {text:?} on {} (shown: {shown:?})",
            self.model
        )
    }

    /// Await the sync request page, tap `label`, and wait for the home page
    /// so the caller only proceeds once the choice has been dismissed
    async fn choose_sync(&self, label: &str) -> anyhow::Result<Vec<Screen>> {
        let mut visited = Vec::new();

        let events = self.wait_for(SYNC_INFO).await?;
        self.record(&events, &mut visited).await?;

        self.tap_label(&events, label).await?;

        self.wait_for(HOME).await?;
        capture(self.h, &self.screenshots, visited.len()).await?;

        Ok(visited)
    }

    /// Dismiss the blind signing warning that precedes the review, recording it
    /// and leaving the display on the review's first page.
    ///
    /// The warning page has no reject control, so waiting for one is how the
    /// review is known to have started -- without it the first
    /// [navigate][Self::navigate] poll can still see the warning and swipe
    /// straight past the review's opening page.
    async fn enter_blind_review(&self, visited: &mut Vec<Screen>) -> anyhow::Result<()> {
        let warn = self.wait_for(TX_BLIND_WARN).await?;
        self.record(&warn, visited).await?;

        self.tap_label(&warn, TX_BLIND_CONTINUE).await?;

        self.wait_for(TX_REJECT).await?;

        Ok(())
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
        debug!("UI: approve transaction");

        let mut visited = Vec::new();

        self.enter_blind_review(&mut visited).await?;

        // Swipe through the review to the long press page
        let finish = self.navigate(TX_HOLD, &mut visited).await?;
        self.record(&finish, &mut visited).await?;

        self.hold_label(&finish, TX_HOLD).await?;

        // Wait for the status page so the caller only proceeds once the
        // engine has been told
        self.wait_for(TX_SIGNED).await?;
        capture(self.h, &self.screenshots, visited.len()).await?;

        Ok(visited)
    }

    async fn reject_tx(&self) -> anyhow::Result<Vec<Screen>> {
        debug!("UI: reject transaction");

        let mut visited = Vec::new();

        // Continue past the warning rather than taking `TX_BLIND_BACK`, so the
        // rejection is exercised from the review itself
        self.enter_blind_review(&mut visited).await?;

        // The reject control sits in the review footer, present on every page
        let page = self.navigate(TX_REJECT, &mut visited).await?;
        self.record(&page, &mut visited).await?;

        self.tap_label(&page, TX_REJECT).await?;

        let confirm = self.wait_for(TX_REJECT_YES).await?;
        self.record(&confirm, &mut visited).await?;

        self.tap_label(&confirm, TX_REJECT_YES).await?;

        self.wait_for(TX_REJECTED).await?;
        capture(self.h, &self.screenshots, visited.len()).await?;

        Ok(visited)
    }

    async fn approve_ident(&self) -> anyhow::Result<Vec<Screen>> {
        Err(self.unimplemented("identity approval"))
    }
}
