use core::sync::atomic::{AtomicBool, Ordering};
use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::{nbgl::{NbglHomeAndSettings, NbglStatus}, screen::sdk_screen_clear};

use ledger_mob_core::engine::{Driver, Engine};

use crate::{
    settings::{Settings, SETTINGS_STRINGS},
    APP_VERSION,
};

mod sync_request;
pub use sync_request::SyncRequest;

static SHOW_ADDRESS: AtomicBool = AtomicBool::new(false);

pub fn take_show_address_request() -> bool { SHOW_ADDRESS.swap(false, Ordering::Relaxed) }

/// Top level User Interface implementation
pub struct Ui {
    /// Current top-level state of UI
    pub state: UiState,

    /// Last state (determines if we need to redraw the screen)
    pub last_state: UiStateKind,
}

pub enum UiState {
    /// Showing main menu
    Menu(NbglHomeAndSettings),

    /// Showing a b58 address
    // TODO: just using an existing type here to test the trigger
    Address(NbglStatus),

    KeyRequest(SyncRequest),

    TxBlindRequest(()),

    TxSummaryRequest(()),

    IdentRequest(()),

    /// Display progress
    Progress,

    /// Display a message
    Message(&'static str),
}

impl core::fmt::Debug for UiState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UiState::Menu(_) => write!(f, "Menu"),
            UiState::Address(_) => write!(f, "Address"),
            UiState::KeyRequest(_) => write!(f, "KeyRequest"),
            UiState::TxBlindRequest(_) => write!(f, "TxBlindRequest"),
            UiState::TxSummaryRequest(_) => write!(f, "TxSummaryRequest"),
            UiState::IdentRequest(_) => write!(f, "IdentRequest"),
            UiState::Progress => write!(f, "Progress"),
            UiState::Message(_) => write!(f, "Message"),
        }
    }
}

/// A data-free enumeration of the UI states
#[derive(Copy, Clone, Debug, PartialEq)]
enum UiStateKind {
    None,
    Menu,
    Address,
    KeyRequest,
    TxBlindRequest,
    TxSummaryRequest,
    IdentRequest,
    Progress,
    Message,
}

impl Ui {
    /// Create a new [Ui] instance
    pub fn new() -> Self {
        Self {
            state: UiState::menu(),
            last_state: UiStateKind::None,
        }
    }

    /// Initialise a UI instance without double stack allocations
    pub unsafe fn init(p: *mut Self) {
        core::ptr::write(p, Self::new());
    }

    /// Handle touch events (update internal state based on flags set in UI callbacks)
    pub fn handle_touch(&mut self) -> bool {
        ledger_device_sdk::log::debug!("Handling touch in state {:?}", self.state);
        match self.state {
            UiState::Menu(_) if take_show_address_request() => {
                ledger_device_sdk::log::debug!("Switching to Address UI");
                self.state = UiState::address();
                return true;
            }
            UiState::Address(_) => {
                ledger_device_sdk::log::debug!("Touch event in Address UI");
                // TODO: temporary logic for testing UI things
                self.state = UiState::menu();
                return true;
            }
            _ => (),
        }
        false
    }

    /// Render the [Ui] using the current state
    #[inline(never)]
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&mut self, engine: &mut Engine<D, R>) {
        ledger_device_sdk::log::debug!("UI render: {:?} (last: {:?})", self.state, self.last_state);

        match &mut self.state {
            // TODO: all this
            UiState::Menu(page) if self.last_state != UiStateKind::Menu => {
                ledger_device_sdk::log::debug!("Rendering Menu UI");
                self.last_state = UiStateKind::Menu;

                page.show_and_return();
            }
            UiState::Address(page) if self.last_state != UiStateKind::Address => {
                ledger_device_sdk::log::debug!("Rendering Address UI");

                self.last_state = UiStateKind::Address;
                
                page.show(true);
            }
            UiState::KeyRequest(s) if self.last_state != UiStateKind::KeyRequest => {
                ledger_device_sdk::log::debug!("Rendering KeyRequest UI");

                self.last_state = UiStateKind::KeyRequest;

                match s.show_blocking() {
                    true => engine.unlock(),
                    false => engine.lock(),
                }

                ledger_device_sdk::log::debug!("Finished KeyRequest UI");

                self.state = UiState::menu();
                if let UiState::Menu(page) = &mut self.state {
                    page.show_and_return();
                }
            }
            _ => (),
        }
    }
}

impl UiState {
    pub fn kind(&self) -> UiStateKind {
        match self {
            UiState::Menu(_) => UiStateKind::Menu,
            UiState::Address(_) => UiStateKind::Address,
            UiState::KeyRequest(_) => UiStateKind::KeyRequest,
            UiState::TxBlindRequest(_) => UiStateKind::TxBlindRequest,
            UiState::TxSummaryRequest(_) => UiStateKind::TxSummaryRequest,
            UiState::IdentRequest(_) => UiStateKind::IdentRequest,
            UiState::Progress => UiStateKind::Progress,
            UiState::Message(_) => UiStateKind::Message,
        }
    }

    pub fn menu() -> Self {
        let mut settings = Settings::default();

        let page = NbglHomeAndSettings::new()
            .glyph(&crate::consts::MOB128X128)
            .infos("MobileCoin", APP_VERSION, "MobileCoin LLC.")
            .tagline("Testing 123")
            .settings(settings.get_mut(), SETTINGS_STRINGS)
            .action("Test Action", || {
                ledger_device_sdk::log::debug!("Test Action triggered");
                SHOW_ADDRESS.store(true, Ordering::Relaxed);
            });

        Self::Menu(page)
    }

    pub fn address() -> Self {
        Self::Address(NbglStatus::new().text("Testing 345"))
    }

    pub fn key_request() -> Self {
        Self::KeyRequest(SyncRequest::new())
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
