// Copyright (c) 2022-2023 The MobileCoin Foundation

use rand_core::{CryptoRng, RngCore};

use emstr::{helpers::Hex, EncodeStr};

use ledger_device_sdk::buttons::ButtonEvent;

use ledger_device_sdk::ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::engine::{Driver, Engine};

use super::{
    clear_screen,
    helpers::{tx_approve_page, tx_deny_page},
    UiResult,
};

/// UI Approval Element
///
/// Used for user-confirmation of key requests (and transactions, pending TxSummary availability)
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TxBlindApprover {
    state: ApproverState,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum ApproverState {
    Init,
    Warn,
    Hash,
    Allow,
    Deny,
}

impl TxBlindApprover {
    /// Create a new Approver with the provided message
    pub fn new() -> Self {
        Self {
            state: ApproverState::Init,
        }
    }

    /// Update [Approver] state, handling button events and returning the
    /// approval state on exit
    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<bool> {
        match (self.state, btn) {
            // Init state, right button moves to warning
            (ApproverState::Init, ButtonEvent::RightButtonRelease) => {
                self.state = ApproverState::Warn
            }

            // Warning message, right button moves to hash display
            (ApproverState::Warn, ButtonEvent::LeftButtonRelease) => {
                self.state = ApproverState::Init
            }
            (ApproverState::Warn, ButtonEvent::RightButtonRelease) => {
                self.state = ApproverState::Hash
            }

            // Hash display, left back to warning, right to allow
            (ApproverState::Hash, ButtonEvent::LeftButtonRelease) => {
                self.state = ApproverState::Warn
            }
            (ApproverState::Hash, ButtonEvent::RightButtonRelease) => {
                self.state = ApproverState::Allow
            }

            // Allow state, left back to hash, both to approve, right to deny
            (ApproverState::Allow, ButtonEvent::LeftButtonRelease) => {
                self.state = ApproverState::Hash
            }
            (ApproverState::Allow, ButtonEvent::BothButtonsRelease) => return UiResult::Exit(true),
            (ApproverState::Allow, ButtonEvent::RightButtonRelease) => {
                self.state = ApproverState::Deny
            }

            // Deny state, left back to allow, both to cancel
            (ApproverState::Deny, ButtonEvent::LeftButtonRelease) => {
                self.state = ApproverState::Allow
            }
            (ApproverState::Deny, ButtonEvent::BothButtonsRelease) => return UiResult::Exit(false),

            // All other states, both buttons exit and cancel transaction
            (_, ButtonEvent::BothButtonsRelease) => return UiResult::Exit(false),
            _ => return UiResult::None,
        }

        UiResult::Update
    }

    /// Render the [Approver] based on it's current internal state
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, engine: &Engine<D, R>) {
        use ApproverState::*;

        let mut buff = [0u8; 32];

        // Clear screen prior to display
        clear_screen();

        // Display arrows
        if self.state != Init {
            LEFT_ARROW.shift_v(0).display();
        }
        if self.state != Deny {
            RIGHT_ARROW.shift_v(0).display();
        }

        // Display pages
        match self.state {
            Init => {
                ["Transaction", "Request"].place(Location::Middle, Layout::Centered, false);
            }
            Warn => {
                [
                    "No summary available,",
                    "please verify the",
                    "transaction hash",
                ]
                .place(Location::Middle, Layout::Centered, false);
            }
            Hash => {
                // Fetch message from engine
                let msg = engine.message();
                let msg_str = fmt_msg(msg, &mut buff);

                // Display message
                ["Transaction hash:", msg_str].place(Location::Middle, Layout::Centered, false);
            }
            Deny => {
                tx_deny_page();
            }
            Allow => {
                tx_approve_page();
            }
        }

        // Update screen
        screen_util::screen_update();
    }
}

fn fmt_msg<'a>(msg: Option<&[u8]>, buff: &'a mut [u8]) -> &'a str {
    let msg = match msg {
        Some(v) => v,
        None => return "NO_MSG",
    };

    let n = match emstr::write!(
        &mut buff[..],
        Hex(&msg[..4]),
        "...",
        Hex(&msg[msg.len() - 4..])
    ) {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match core::str::from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}
