// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ledger MobileCoin User Interface
//!

use rand_core::{CryptoRng, RngCore};

use ledger_mob_core::engine::{Driver, Engine};

use nanos_ui::{bagls::RectFull, layout::Draw, SCREEN_HEIGHT, SCREEN_WIDTH};

mod helpers;
pub use helpers::*;

mod menu;
pub use menu::*;

mod approver;
pub use approver::*;

mod progress;
pub use progress::*;

mod complete;
pub use complete::*;

mod tx_blind_approver;
pub use tx_blind_approver::*;

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

    /// UI menu instance (independently persistet state)
    pub menu: UiMenu,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum UiState {
    /// Showing main menu
    Menu,

    /// Request for view keys, awaiting user input
    KeyRequest(Approver),

    /// Transaction request without summary, awaiting user input
    TxRequest(TxBlindApprover),

    /// Transaction request with summary, awaiting user input
    #[cfg(feature = "summary")]
    TxSummaryRequest(TxSummaryApprover),

    #[cfg(feature = "ident")]
    IdentRequest(IdentApprover),

    /// Progress indicator
    Progress(Progress),

    /// Transaction complete
    Complete(Complete),
}

impl UiState {
    pub fn is_key_request(&self) -> bool {
        matches!(self, UiState::KeyRequest(..))
    }

    pub fn is_tx_request(&self) -> bool {
        match self {
            UiState::TxRequest(..) => true,
            #[cfg(feature = "summary")]
            UiState::TxSummaryRequest(..) => true,
            _ => false,
        }
    }

    pub fn is_progress(&self) -> bool {
        matches!(self, UiState::Progress(..))
    }

    pub fn is_complete(&self) -> bool {
        matches!(self, UiState::Complete(..))
    }

    #[cfg(feature = "ident")]
    pub fn is_ident_request(&self) -> bool {
        matches!(self, UiState::IdentRequest(..))
    }
}

impl Ui {
    /// Create a new [Ui] instance
    pub fn new() -> Self {
        Self {
            state: UiState::Menu,
            menu: UiMenu::default(),
        }
    }

    /// Render the [Ui] using the current state
    #[inline(never)]
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, engine: &Engine<D, R>) {
        match self.state {
            UiState::Menu => self.menu.render(engine),
            UiState::KeyRequest(a) => a.render(engine),
            UiState::TxRequest(a) => a.render(engine),
            #[cfg(feature = "summary")]
            UiState::TxSummaryRequest(a) => a.render(engine),
            #[cfg(feature = "ident")]
            UiState::IdentRequest(a) => a.render(engine),
            UiState::Progress(a) => a.render(engine),
            UiState::Complete(a) => a.render(engine),
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

/// Clear screen wrapper that works both on hardware and speculos
/// (required as speculos doesn't support the full screen clear syscall,
/// and we want to run _exactly_ the same code on both)
pub fn clear_screen() {
    RectFull::new()
        .width(SCREEN_WIDTH as u32)
        .height(SCREEN_HEIGHT as u32)
        .erase();
}
