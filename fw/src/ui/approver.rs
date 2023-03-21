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

/// UI Approval Element
///
/// Used for user-confirmation of key requests (and transactions, pending TxSummary availability)
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Approver {
    message: &'static str,
    state: ApproverState,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ApproverState {
    Deny,
    Allow,
}

impl Approver {
    /// Create a new Approver with the provided message
    pub fn new(message: &'static str) -> Self {
        Self {
            message,
            state: ApproverState::Deny,
        }
    }

    /// Update [Approver] state, handling button events and returning the
    /// approval state on exit
    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<bool> {
        match (self.state, btn) {
            (ApproverState::Deny, ButtonEvent::BothButtonsRelease) => UiResult::Exit(false),
            (ApproverState::Deny, ButtonEvent::RightButtonRelease) => {
                self.state = ApproverState::Allow;
                UiResult::Update
            }
            (ApproverState::Allow, ButtonEvent::BothButtonsRelease) => UiResult::Exit(true),
            (ApproverState::Allow, ButtonEvent::LeftButtonRelease) => {
                self.state = ApproverState::Deny;
                UiResult::Update
            }
            _ => UiResult::None,
        }
    }

    /// Render the [Approver] based on it's current internal state
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, _engine: &Engine<D, R>) {
        use ApproverState::*;

        clear_screen();

        self.message
            .place(Location::Custom(8), Layout::Centered, false);

        match self.state {
            Deny => {
                //bitmaps::CROSS.draw((128 - 32) / 2, 24);
                RIGHT_ARROW.shift_v(12).display();
                CROSS_ICON.shift_v(4).shift_h((128 - 16) / 2).display();

                "REJECT".place(Location::Custom(48), Layout::Centered, false);
            }
            Allow => {
                LEFT_ARROW.shift_v(12).display();
                CHECKMARK_ICON.shift_v(4).shift_h((128 - 16) / 2).display();

                //bitmaps::CHECKMARK.draw((128 - 32) / 2, 24);
                "APPROVE".place(Location::Custom(48), Layout::Centered, false);
            }
        }

        screen_util::screen_update();
    }
}
