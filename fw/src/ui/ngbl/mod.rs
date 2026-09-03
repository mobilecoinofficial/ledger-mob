

use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::{screen::sdk_screen_clear, nbgl::NbglHomeAndSettings};

use ledger_mob_core::engine::{Driver, Engine};

use crate::{MOB64X64, APP_VERSION};

/// Top level User Interface implementation
pub struct Ui {
    /// Current top-level state of UI
    pub state: UiState,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UiState {
    /// Showing main menu
    Menu,

    /// Showing a b58 address
    Address,

    KeyRequest(()),

    TxBlindRequest(()),

    TxSummaryRequest(()),

    IdentRequest(()),

    /// Display progress
    Progress,

    /// Display a message
    Message(
        &'static str,
    ),
}

impl Ui {
    /// Create a new [Ui] instance
    pub const fn new() -> Self {
        Self {
            state: UiState::Menu,
        }
    }

    /// Initialise a UI instance without double stack allocations
    pub unsafe fn init(p: *mut Self) {
        core::ptr::write(p, Self::new());
    }

    /// Render the [Ui] using the current state
    #[inline(never)]
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&mut self, engine: &Engine<D, R>) {
        match &mut self.state {
            // TODO: all this
            _ => {
                NbglHomeAndSettings::new()
                    .glyph(&MOB64X64)
                    .infos(
                        "MobileCoin",
                        APP_VERSION,
                        "MobileCoin LLC.",
                    )
                    .show_and_return();
            }
        } 
    }
}

impl UiState {
    pub fn menu() -> Self {
        Self::Menu
    }

    pub fn key_request() -> Self {
        // TODO
        Self::KeyRequest(())
    }

    pub fn is_key_request(&self) -> bool {
        matches!(self, UiState::KeyRequest(..))
    }

    #[cfg(feature = "ident")]
    pub fn ident_request() -> Self {
        // TODO
        Self::IdentRequest(())
    }

    #[cfg(feature = "ident")]
    pub fn is_ident_request(&self) -> bool {
        matches!(self, UiState::IdentRequest(..))
    }

    pub fn message(msg: &'static str) -> Self {
        Self::Message(msg)
    }

    pub fn is_message(&self) -> bool {
        matches!(self, UiState::Message(..))
    }

    pub fn progress() -> Self {
        Self::Progress
    }

    pub fn is_progress(&self) -> bool {
        matches!(self, UiState::Progress)
    }
    
    pub fn tx_blind_request() -> Self {
        // TODO
        Self::TxBlindRequest(())
    }

    #[cfg(feature = "summary")]
    pub fn tx_summary_request(num_outputs: usize, num_totals: usize) -> Self {
        // TODO
        Self::TxSummaryRequest(())
    }

    pub fn is_tx_request(&self) -> bool {
        match self {
            UiState::TxBlindRequest(..) => true,
            #[cfg(feature = "summary")]
            UiState::TxSummaryRequest(..) => true,
            _ => false,
        }
    }
}


pub fn clear_screen() {
    // Does this still exist?
}

pub fn show_pending_review() {
    // TODO
}

pub fn show_rng_error() {
    // TODO
}