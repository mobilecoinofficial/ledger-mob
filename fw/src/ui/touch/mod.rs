use core::sync::atomic::{AtomicBool, Ordering};
use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::{nbgl::NbglHomeAndSettings, screen::sdk_screen_clear};

use ledger_mob_core::engine::{Driver, Engine, FogId};
use mc_core::{account::PublicSubaddress, consts::DEFAULT_SUBADDRESS_INDEX};

use crate::{
    platform::platform_get_fog_id,
    settings::{Settings, SETTINGS_STRINGS},
    APP_VERSION,
};

mod message;
pub use message::Message;

mod sync_request;
pub use sync_request::SyncRequest;

mod address;
pub use address::{AddressEvent, AddressView};

static SHOW_ADDRESS: AtomicBool = AtomicBool::new(false);

pub fn take_show_address_request() -> bool {
    SHOW_ADDRESS.swap(false, Ordering::Relaxed)
}

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
    Address(AddressView),

    KeyRequest(SyncRequest),

    TxBlindRequest(()),

    TxSummaryRequest(()),

    IdentRequest(()),

    /// Display progress
    Progress,

    /// Display a message
    Message(Message),
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
    pub fn handle_touch<D: Driver, R: RngCore + CryptoRng>(
        &mut self,
        engine: &mut Engine<D, R>,
    ) -> bool {
        ledger_device_sdk::log::debug!("Handling touch in state {:?}", self.state);

        match &mut self.state {
            // In the menu state, check if there's a pending request to show the address
            // and switch to the address view if so
            UiState::Menu(_) if take_show_address_request() => {
                ledger_device_sdk::log::debug!("Switching to Address UI");

                // Fetch subaddress from engine
                let fog_id = platform_get_fog_id();
                let s = engine.get_subaddress(0, DEFAULT_SUBADDRESS_INDEX, fog_id);

                self.state = UiState::address(
                    &s.address,
                    s.fog_id,
                    s.fog_sig.as_ref().map(|s| s.as_slice()).unwrap_or(&[]),
                );
                return true;
            }
            // In the address state, handle touch events for the address view
            // (navigation is handled in nbgl, we only see Exit and Update events here.)
            UiState::Address(view) => {
                ledger_device_sdk::log::debug!("Touch event in Address UI");

                match view.handle_event() {
                    // Return to the menu when the user exits the page
                    AddressEvent::Exit => {
                        self.state = UiState::menu();
                        return true;
                    }
                    // Draw the new page on navigation
                    AddressEvent::Update => return true,
                    AddressEvent::None => (),
                }

                // Otherwise redraw if something has taken over the screen
                if !view.is_live() {
                    return true;
                }
            }
            // Any touch event in the message view dismisses the message
            UiState::Message(m) => {
                m.take_dismiss();
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
            UiState::Address(view)
                if self.last_state != UiStateKind::Address || !view.is_live() =>
            {
                ledger_device_sdk::log::debug!("Rendering Address UI");

                self.last_state = UiStateKind::Address;

                if let Err(_e) = view.draw() {
                    ledger_device_sdk::log::debug!("Address page draw failed: {:?}", _e);
                }
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
            // Messages are drawn without blocking, and (re)drawn whenever
            // they are not live (ie. if displaced by the lock screen).
            // Dismissal is handled via `handle_touch` or the message timeout in `main.rs`.
            UiState::Message(m) => {
                self.last_state = UiStateKind::Message;

                #[allow(unused_variables)]
                if let Err(e) = m.draw() {
                    #[cfg(feature = "debug")]
                    ledger_device_sdk::log::debug!("Failed to draw message: {:?}", e);
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
            .action("Show Address", || {
                ledger_device_sdk::log::debug!("Show Address triggered");
                SHOW_ADDRESS.store(true, Ordering::Relaxed);
            });

        Self::Menu(page)
    }

    pub fn address(address: &PublicSubaddress, fog_id: FogId, fog_authority_sig: &[u8]) -> Self {
        Self::Address(AddressView::new(address, fog_id, fog_authority_sig))
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

    pub fn message(msg: &'static str, success: bool) -> Self {
        Self::Message(Message::new(msg, success))
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
