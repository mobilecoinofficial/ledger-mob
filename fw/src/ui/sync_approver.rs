// Copyright (c) 2022-2023 The MobileCoin Foundation

use rand_core::{CryptoRng, RngCore};

use nanos_sdk::buttons::ButtonEvent;

use nanos_ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use super::clear_screen;
use ledger_mob_core::engine::{Driver, Engine};

use super::UiResult;

/// Wallet sync approval element
///
/// Used for user-confirmation of wallet syncing (view key and key image requests)
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SyncApprover {
    state: ApproverState,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ApproverState {
    Info,
    Allow,
    Deny,
}

impl SyncApprover {
    /// Create a new [SyncApprover] with the provided message
    pub fn new() -> Self {
        Self {
            state: ApproverState::Info,
        }
    }

    /// Update [Approver] state, handling button events and returning the
    /// approval state on exit
    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<bool> {
        match (self.state, btn) {
            // Info, right button to Allow
            (ApproverState::Info, ButtonEvent::RightButtonRelease) => {
                self.state = ApproverState::Allow;
                UiResult::Update
            }
            // Allow, both buttons to approve
            (ApproverState::Allow, ButtonEvent::BothButtonsRelease) => UiResult::Exit(true),
            // .. left button back to Info
            (ApproverState::Allow, ButtonEvent::LeftButtonRelease) => {
                self.state = ApproverState::Info;
                UiResult::Update
            }
            // .. right button to Deny
            (ApproverState::Allow, ButtonEvent::RightButtonRelease) => {
                self.state = ApproverState::Deny;
                UiResult::Update
            }
            // Deny, both buttons to deny
            (ApproverState::Deny, ButtonEvent::BothButtonsRelease) => UiResult::Exit(false),
            // .. left button back to allow
            (ApproverState::Deny, ButtonEvent::LeftButtonRelease) => {
                self.state = ApproverState::Allow;
                UiResult::Update
            }
            _ => UiResult::None,
        }
    }

    /// Render the [Approver] based on it's current internal state
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, _engine: &Engine<D, R>) {
        use ApproverState::*;

        clear_screen();

        // Show arrows
        if self.state != Info {
            LEFT_ARROW.display();
        }
        if self.state != Deny {
            RIGHT_ARROW.display();
        }

        match self.state {
            Info => {
                "Sync Wallet?".place(Location::Custom(8), Layout::Centered, true);
                let lines = [
                    "Allows the connected",
                    "application to view",
                    "account balances",
                ];

                for (i, l) in lines.iter().enumerate() {
                    l.place(Location::Custom(22 + i * 10), Layout::Centered, false);
                }
            }
            Allow => {
                CHECKMARK_ICON.shift_v(-8).shift_h((128 - 16) / 2).display();
                "Approve Sync".place(Location::Custom(34), Layout::Centered, false);
            }
            Deny => {
                CROSS_ICON.shift_v(-8).shift_h((128 - 16) / 2).display();
                "Reject Sync".place(Location::Custom(34), Layout::Centered, false);
            }
        }

        screen_util::screen_update();
    }
}
