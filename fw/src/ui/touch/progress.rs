// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Progress page for touch devices.
//!
//! Shown while the engine is loading or signing a transaction. Built on the
//! non-blocking [`NbglSpinnerPage`] so the app keeps serving APDUs while the
//! spinner is on screen.

use emstr::EncodeStr;
use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::nbgl::NbglSpinnerPage;

use ledger_mob_core::engine::{Driver, Engine, State};

/// Maximum length of the formatted percentage (`"100%"`)
const PCT_LEN: usize = 4;

/// Non-blocking progress view
///
/// The spinner animates itself: `nbgl_layoutAddSpinner` registers a 400ms
/// ticker with NBGL, which turns it as long as the event loop keeps running.
pub struct Progress {
    /// Page state, this must be kept alive while the page is displayed
    /// as NBGL holds pointers into this object
    page: NbglSpinnerPage,

    /// Last (message, percent) written to the page, used to avoid
    /// redundant updates as `main.rs` re-renders on every APDU
    last: Option<(&'static str, Option<usize>)>,
}

impl Progress {
    pub fn new() -> Self {
        Self {
            page: NbglSpinnerPage::new(),
            last: None,
        }
    }

    /// Draw or update the page, returning immediately
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&mut self, engine: &Engine<D, R>) {
        // Resolve message based on engine state
        let message = match engine.state() {
            #[cfg(feature = "summary")]
            State::Summary(_) => "Loading Transaction",
            #[cfg(feature = "mlsag")]
            State::SignRing(_) => "Signing Transaction",
            _ => "Please Wait",
        };

        let progress = engine.progress();

        // Format progress percentage, empty while the engine has none to report
        let mut buff = [0u8; PCT_LEN];
        let sub_text = match progress {
            Some(v) => percent_str(&mut buff, v),
            None => "",
        };

        // Redraw when first shown, or when something has taken over the screen
        // (eg. the lock screen), otherwise update in place on changes only
        if !self.page.is_live() {
            if let Err(_e) = self.page.draw(message, sub_text) {
                #[cfg(feature = "debug")]
                ledger_device_sdk::log::debug!("Progress page draw failed: {:?}", _e);
                return;
            }
        } else if self.last != Some((message, progress)) {
            self.page.update(message, sub_text);
        } else {
            return;
        }

        self.last = Some((message, progress));
    }
}

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a percentage as `"45%"` into the provided buffer
fn percent_str(buff: &mut [u8; PCT_LEN], v: usize) -> &str {
    let n = match emstr::write!(&mut buff[..], v, '%') {
        Ok(n) => n,
        Err(_) => return "",
    };

    // SAFETY: `emstr` only writes ASCII digits and '%' here
    unsafe { core::str::from_utf8_unchecked(&buff[..n]) }
}
