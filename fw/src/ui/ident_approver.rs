// Copyright (c) 2022-2023 The MobileCoin Foundation

use emstr::{helpers::Hex, EncodeStr};
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
pub struct IdentApprover {
    state: ApproverState,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum ApproverState {
    Init,
    Uri,
    Challenge,
    Deny,
    Allow,
}

impl IdentApprover {
    /// Create a new Approver with the provided message
    pub fn new() -> Self {
        Self {
            state: ApproverState::Init,
        }
    }

    /// Update [Approver] state, handling button events and returning the
    /// approval state on exit
    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<bool> {
        use ApproverState::*;
        use ButtonEvent::*;

        let state = match (self.state, btn) {
            (Init, RightButtonRelease) => ApproverState::Uri,

            (Uri, LeftButtonRelease) => ApproverState::Init,
            (Uri, RightButtonRelease) => ApproverState::Challenge,

            (Challenge, LeftButtonRelease) => ApproverState::Uri,
            (Challenge, RightButtonRelease) => ApproverState::Deny,

            (Deny, LeftButtonRelease) => ApproverState::Uri,
            (Deny, BothButtonsRelease) => return UiResult::Exit(false),
            (Deny, RightButtonRelease) => ApproverState::Allow,

            (Allow, LeftButtonRelease) => ApproverState::Deny,
            (Allow, BothButtonsRelease) => return UiResult::Exit(true),

            _ => self.state,
        };

        if state != self.state {
            self.state = state;
            UiResult::Update
        } else {
            UiResult::None
        }
    }

    /// Render the [Approver] based on it's current internal state
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, engine: &Engine<D, R>) {
        use ApproverState::*;

        let mut buff = [0u8; 20];

        clear_screen();

        // Display arrows
        if self.state != ApproverState::Init {
            LEFT_ARROW.shift_v(0).display();
        }
        if self.state != ApproverState::Allow {
            RIGHT_ARROW.shift_v(0).display();
        }

        // Display information
        match self.state {
            Init => {
                ["Identity", "Request"].place(Location::Middle, Layout::Centered, false);
            }
            Uri => {
                let ident = engine.ident().unwrap();
                let uri = ident.uri();

                if uri.len() < 16 {
                    ["URI", uri].place(Location::Middle, Layout::Centered, false);
                } else if uri.len() < 32 {
                    ["URI", &uri[..16], &uri[16..uri.len()]].place(
                        Location::Middle,
                        Layout::Centered,
                        false,
                    );
                } else {
                    ["URI", &uri[..16], "...", &uri[uri.len() - 16..]].place(
                        Location::Middle,
                        Layout::Centered,
                        false,
                    );
                }
            }
            Challenge => {
                let ident = engine.ident().unwrap();
                let challenge_str = fmt_challenge(ident.challenge(), &mut buff);
                ["Challenge", challenge_str].place(Location::Middle, Layout::Centered, false);
            }
            Deny => {
                "Reject challenge?".place(Location::Custom(16), Layout::Centered, false);
                CROSS_ICON.shift_v(8).shift_h((128 - 16) / 2).display();
            }
            Allow => {
                "Sign challenge?".place(Location::Custom(16), Layout::Centered, false);
                CHECKMARK_ICON.shift_v(8).shift_h((128 - 16) / 2).display();
            }
        }

        screen_util::screen_update();
    }
}

fn fmt_challenge<'a>(challenge: &[u8], buff: &'a mut [u8]) -> &'a str {
    let n = match emstr::write!(
        &mut buff[..],
        Hex(&challenge[..4]),
        "...",
        Hex(&challenge[challenge.len() - 4..])
    ) {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match core::str::from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}
