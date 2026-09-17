// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ledger MobileCoin User Interface
//!

use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::{
    buttons::ButtonEvent,
    ui::layout::{Layout, Location, StringPlace},
};

use ledger_mob_core::engine::{Driver, Engine, FogId};
use mc_core::{account::PublicSubaddress, consts::DEFAULT_SUBADDRESS_INDEX};

use crate::{
    platform::{platform_get_fog_id, platform_set_fog_id},
    LedgerDriver,
};

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

    pub fn app_info() -> Self {
        Self::AppInfo(AppInfo::new())
    }

    pub fn address(address: &PublicSubaddress, fog_id: FogId, fog_authority_sig: &[u8]) -> Self {
        Self::Address(Address::new(address, fog_id, fog_authority_sig))
    }

    /// Create a new `Progress` variant
    pub fn progress() -> Self {
        Self::Progress(Progress::new())
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

    pub fn ident_request() -> Self {
        Self::IdentRequest(IdentApprover::new())
    }

    #[cfg(feature = "ident")]
    pub fn is_ident_request(&self) -> bool {
        matches!(self, UiState::IdentRequest(..))
    }

    pub fn settings(fog_id: FogId) -> Self {
        Self::Settings(Settings::new(fog_id))
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

    /// Handle button events, returning true if UI should be redrawn
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn handle_btn<RNG: RngCore + CryptoRng>(
        &mut self,
        engine: &mut Engine<LedgerDriver, RNG>,
        btn: &ButtonEvent,
    ) -> bool {
        // Handle buttons depending on UI state
        let r = match self.state {
            UiState::Menu => {
                // Handle menu selections
                self.menu.update(btn).map_exit(|v| {
                    match v {
                        MenuState::Address => {
                            // Fetch subaddress from engine
                            let fog_id = platform_get_fog_id();
                            let s = engine.get_subaddress(0, DEFAULT_SUBADDRESS_INDEX, fog_id);

                            // Set UI state to display subaddress
                            self.state = UiState::address(
                                &s.address,
                                s.fog_id,
                                s.fog_sig.as_ref().map(|s| s.as_slice()).unwrap_or(&[]),
                            );
                        }
                        MenuState::Version => self.state = UiState::app_info(),
                        MenuState::Settings => {
                            let fog_id = platform_get_fog_id();
                            self.state = UiState::settings(fog_id)
                        }
                        MenuState::Exit => ledger_device_sdk::exit_app(0),
                        _ => (),
                    }
                });
                // Force redraw
                UiResult::Update
            }
            UiState::Address(ref mut a) => a.update(btn),
            UiState::KeyRequest(ref mut a) => {
                a.update(btn).map_exit(|v| {
                    // Unlock engine on approval
                    if *v {
                        engine.unlock()
                    }
                })
            }
            #[cfg(feature = "ident")]
            UiState::IdentRequest(ref mut a) => {
                a.update(btn).map_exit(|v| {
                    // Set ident approval
                    engine.ident_approve(*v)
                })
            }
            UiState::TxRequest(ref mut a) => {
                a.update(btn).map_exit(|v| {
                    // Approve or deny transaction
                    match *v {
                        true => engine.approve(),
                        false => engine.deny(),
                    }
                })
            }
            #[cfg(feature = "summary")]
            UiState::TxSummaryRequest(ref mut a) => {
                a.update(btn, engine).map_exit(|v| {
                    // Approve or deny transaction
                    match *v {
                        true => engine.approve(),
                        false => engine.deny(),
                    }
                })
            }
            UiState::Progress(ref mut a) => {
                a.update(btn).map_exit(|v| {
                    // Cancel transaction in progress
                    match *v {
                        true => (),
                        false => engine.deny(),
                    }
                })
            }
            UiState::Message(ref mut a) => {
                a.update(btn).map_exit(|_| {
                    // Reset engine on message clear
                    engine.reset()
                })
            }
            UiState::AppInfo(ref mut a) => a.update(btn),
            UiState::Settings(ref mut a) => a.update(btn).map_exit(|fog_id| {
                // Update fog id
                platform_set_fog_id(fog_id);
            }),
        };

        // Handle ui results
        match self.state {
            UiState::Address(..)
            | UiState::KeyRequest(..)
            | UiState::TxRequest(..)
            | UiState::Progress(..)
            | UiState::Message(..)
            | UiState::AppInfo(..)
            | UiState::Settings(..)
                if r.is_exit() =>
            {
                self.state = UiState::Menu;
                true
            }
            #[cfg(feature = "summary")]
            UiState::TxSummaryRequest(..) if r.is_exit() => {
                self.state = UiState::Menu;
                true
            }
            #[cfg(feature = "ident")]
            UiState::IdentRequest(..) if r.is_exit() => {
                self.state = UiState::Menu;
                true
            }
            _ => r == UiResult::Update,
        }
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
