

use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::{screen::sdk_screen_clear, nbgl::NbglHomeAndSettings};
use ledger_device_sdk::nvm::AtomicStorage;
use ledger_device_sdk::NVMData;

use ledger_mob_core::engine::{Driver, Engine};

use crate::{MOB64X64, APP_VERSION, settings::{Settings, SETTINGS_STRINGS}};

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

impl core::fmt::Debug for UiState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UiState::Menu(_) => write!(f, "Menu"),
            UiState::Address => write!(f, "Address"),
            UiState::KeyRequest(_) => write!(f, "KeyRequest"),
            UiState::TxBlindRequest(_) => write!(f, "TxBlindRequest"),
            UiState::TxSummaryRequest(_) => write!(f, "TxSummaryRequest"),
            UiState::IdentRequest(_) => write!(f, "IdentRequest"),
            UiState::Progress => write!(f, "Progress"),
            UiState::Message(_) => write!(f, "Message"),
        }
    }
}

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

    /// Render the [Ui] using the current state
    #[inline(never)]
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&mut self, engine: &Engine<D, R>) {
        #[cfg(feature = "debug")]
        ledger_device_sdk::log::debug!(
            "UI render: {:?} (last: {:?})",
            self.state, self.last_state
        );

        match &mut self.state {
            // TODO: all this
            UiState::Menu(page) if self.last_state != UiStateKind::Menu => {
                self.last_state = UiStateKind::Menu;
                page.show_and_return();
            }
            _ => (),
        } 
    }
}

impl UiState {
    pub fn kind(&self) -> UiStateKind {
        match self {
            UiState::Menu(_) => UiStateKind::Menu,
            UiState::Address => UiStateKind::Address,
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
            .glyph(&MOB64X64)
            .infos(
                "MobileCoin",
                APP_VERSION,
                "MobileCoin LLC.",
            )
            .tagline("Testing 123")
            .settings(settings.get_mut(), SETTINGS_STRINGS);

        Self::Menu(page)
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