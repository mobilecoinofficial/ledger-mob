use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::{
    nbgl::{NbglHomeAndSettings, NbglReviewStatus, StatusType},
    screen::sdk_screen_clear,
};

use ledger_mob_core::engine::{Driver, Engine};

use crate::{
    settings::{Settings, SETTINGS_STRINGS},
    APP_VERSION,
};

mod sync_request;
pub use sync_request::SyncRequest;

mod tx_blind_request;
pub use tx_blind_request::TxBlindRequest;

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

    KeyRequest(SyncRequest),

    /// Transaction request without summary, awaiting user input
    TxBlindRequest(TxBlindRequest),

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

    /// Render the [Ui] using the current state
    #[inline(never)]
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&mut self, engine: &mut Engine<D, R>) {
        #[cfg(feature = "debug")]
        ledger_device_sdk::log::debug!("UI render: {:?} (last: {:?})", self.state, self.last_state);

        match &mut self.state {
            // TODO: all this
            UiState::Menu(page) if self.last_state != UiStateKind::Menu => {
                self.last_state = UiStateKind::Menu;
                page.show_and_return();
            }
            UiState::Address if self.last_state != UiStateKind::Address => {
                self.last_state = UiStateKind::Address;
                // TODO: Render the address page here
            }
            UiState::KeyRequest(s) if self.last_state != UiStateKind::KeyRequest => {
                self.last_state = UiStateKind::KeyRequest;
                #[cfg(feature = "debug")]
                ledger_device_sdk::log::debug!("Rendering KeyRequest UI");

                match s.show_blocking() {
                    true => engine.unlock(),
                    false => engine.lock(),
                }

                #[cfg(feature = "debug")]
                ledger_device_sdk::log::debug!("Finished KeyRequest UI");

                self.state = UiState::menu();
                if let UiState::Menu(page) = &mut self.state {
                    page.show_and_return();
                }
            }
            UiState::TxBlindRequest(s) if self.last_state != UiStateKind::TxBlindRequest => {
                self.last_state = UiStateKind::TxBlindRequest;
                #[cfg(feature = "debug")]
                ledger_device_sdk::log::debug!("Rendering TxBlindRequest UI");

                // Show the blind signing review, blocking until the user chooses
                let approved = s.show_blocking(engine);

                // Update the engine state based on the user's choice
                match approved {
                    true => engine.approve(),
                    false => engine.deny(),
                }

                // Then show the approved state
                // TODO(ryan): should this status change happen elsewhere?
                NbglReviewStatus::new()
                    .status_type(StatusType::Transaction)
                    .show(approved);

                #[cfg(feature = "debug")]
                ledger_device_sdk::log::debug!(
                    "Finished TxBlindRequest UI (approved: {})",
                    approved
                );

                match approved {
                    // On approval the host immediately drives ring signing, so we move to the progress state.
                    true => self.state = UiState::progress(),
                    // On rejection return to the menu and leave the engine in `Deny`
                    // for the host to observe.
                    false => {
                        self.state = UiState::menu();
                        if let UiState::Menu(page) = &mut self.state {
                            page.show_and_return();
                        }
                    }
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
            .glyph(&crate::consts::MOB128X128)
            .infos("MobileCoin", APP_VERSION, "MobileCoin LLC.")
            .tagline("Testing 123")
            .settings(settings.get_mut(), SETTINGS_STRINGS);

        Self::Menu(page)
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
        Self::TxBlindRequest(TxBlindRequest::new())
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
