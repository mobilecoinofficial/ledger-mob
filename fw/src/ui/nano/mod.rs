// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ledger MobileCoin User Interface
//!

use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::ui::layout::{Layout, Location, StringPlace};

use ledger_mob_core::engine::{Driver, Engine};

mod helpers;
pub use helpers::*;

mod menu;
pub use menu::*;

mod sync_approver;
pub use sync_approver::*;

mod progress;
pub use progress::*;

mod message;
pub use message::*;

mod tx_blind_approver;
pub use tx_blind_approver::*;

mod address;
pub use address::*;

mod app_info;
pub use app_info::*;

mod settings;
pub use settings::*;

#[cfg(feature = "summary")]
mod tx_summary_approver;
#[cfg(feature = "summary")]
pub use tx_summary_approver::*;

#[cfg(feature = "ident")]
mod ident_approver;
#[cfg(feature = "ident")]
pub use ident_approver::*;

/// Top level User Interface implementation
pub struct Ui {
    /// Current top-level state of UI
    pub state: UiState,

    /// UI menu instance (independently persistent state)
    pub menu: UiMenu,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UiState {
    /// Showing main menu
    Menu,

    /// Showing a b58 address
    Address(Address<512>),

    /// Request for view keys, awaiting user input
    KeyRequest(SyncApprover),

    /// Transaction request without summary, awaiting user input
    TxRequest(TxBlindApprover),

    /// Transaction request with summary, awaiting user input
    #[cfg(feature = "summary")]
    TxSummaryRequest(TxSummaryApprover),

    #[cfg(feature = "ident")]
    IdentRequest(IdentApprover),

    /// Progress indicator
    Progress(Progress),

    /// Messages (transaction complete, rejected, etc.)
    Message(Message),

    /// App information
    AppInfo(AppInfo),

    /// Settings
    Settings(Settings),
}

impl UiState {
    pub fn menu() -> Self {
        Self::Menu
    }

    /// Create a new `Progress` variant
    pub fn progress() -> Self {
        Self::Progress
    }

    pub fn is_progress(&self) -> bool {
        matches!(self, UiState::Progress(..))
    }

    /// Create a new `Message` variant
    pub fn message(value: &'static str) -> Self {
        Self::Message(Message::new(value))
    }

    pub fn is_message(&self) -> bool {
        matches!(self, UiState::Message(..))
    }

    /// Create a new `KeyRequest` variant
    pub fn key_request() -> Self {
        Self::KeyRequest(SyncApprover::new())
    }

    pub fn is_key_request(&self) -> bool {
        matches!(self, UiState::KeyRequest(..))
    }

    pub fn tx_blind_request() -> Self {
        Self::TxRequest(TxBlindApprover::new())
    }

    #[cfg(feature = "summary")]
    pub fn tx_summary_request(num_outputs: usize, num_totals: usize) -> Self {
        Self::TxSummaryRequest(TxSummaryApprover::new(num_outputs, num_totals))
    }

    pub fn is_tx_request(&self) -> bool {
        match self {
            UiState::TxRequest(..) => true,
            #[cfg(feature = "summary")]
            UiState::TxSummaryRequest(..) => true,
            _ => false,
        }
    }

    #[cfg(feature = "ident")]
    pub fn is_ident_request(&self) -> bool {
        matches!(self, UiState::IdentRequest(..))
    }
}

impl Ui {
    /// Create a new [Ui] instance
    pub const fn new() -> Self {
        Self {
            state: UiState::Menu,
            menu: UiMenu::new(),
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
            UiState::Menu => self.menu.render(engine),
            UiState::Address(a) => a.render(engine),
            UiState::KeyRequest(a) => a.render(engine),
            UiState::TxRequest(a) => a.render(engine),
            #[cfg(feature = "summary")]
            UiState::TxSummaryRequest(a) => a.render(engine),
            #[cfg(feature = "ident")]
            UiState::IdentRequest(a) => a.render(engine),
            UiState::Progress(a) => a.render(engine),
            UiState::Message(a) => a.render(engine),
            UiState::AppInfo(a) => a.render(engine),
            UiState::Settings(a) => a.render(engine),
        }
    }
}

pub trait Element {
    /// Event type for updates
    type Event;

    /// Context for renderer
    type Context;

    /// Handle an event, updating element state or exiting
    fn update(&mut self, evt: Self::Event);

    /// Draw element
    fn draw(&self, ctx: Self::Context);
}

/// Result type for Ui elements
///
/// Indicates whether a redraw is required or if the element has
/// been exited returning a value, for example, a bool on success / failure.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum UiResult<R = ()> {
    /// None indicates no change
    None,
    /// Update indicates UI should be redrawn
    Update,
    /// Exit used to signal element exit
    Exit(R),
}

impl<R> UiResult<R> {
    /// Map on UiResult exit value
    pub fn map_exit<O>(&self, mut f: impl FnMut(&R) -> O) -> UiResult<O> {
        match self {
            UiResult::None => UiResult::None,
            UiResult::Update => UiResult::Update,
            UiResult::Exit(ref v) => {
                let o = f(v);
                UiResult::Exit(o)
            }
        }
    }

    /// Check if a UiResult is the `Exit` variant
    pub fn is_exit(&self) -> bool {
        matches!(self, UiResult::Exit(..))
    }
}

pub fn show_pending_review() {
    "Pending Review".place(Location::Middle, Layout::Centered, false);
}

pub fn show_rng_error() {
    "ERROR".place(Location::Top, Layout::Centered, true);
    "RNG UNAVAILABLE".place(Location::Middle, Layout::Centered, false);
    "EXIT?".place(Location::Bottom, Layout::Centered, false);
}
