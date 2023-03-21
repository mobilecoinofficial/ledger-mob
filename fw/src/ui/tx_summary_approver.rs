// Copyright (c) 2022-2023 The MobileCoin Foundation

use core::str::from_utf8;

use rand_core::{CryptoRng, RngCore};
use strum::{Display, EnumCount};

use emstr::{helpers::Hex, EncodeStr};

use nanos_sdk::buttons::ButtonEvent;

use nanos_ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::{
    engine::{Driver, Engine, TransactionEntity},
    helpers::fmt_token_val,
};

use super::{
    clear_screen,
    helpers::{tx_approve_page, tx_deny_page},
    UiResult,
};

/// UI Approval Element
///
/// Used for user-confirmation of key requests (and transactions, pending TxSummary availability)
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TxSummaryApprover {
    op_count: usize,
    state: TxSummaryApproverState,
}

#[derive(Copy, Clone, Debug, PartialEq, Display, EnumCount)]
pub enum TxSummaryApproverState {
    Init,
    Op(usize),
    Fee,
    Allow,
    Deny,
}

impl TxSummaryApprover {
    /// Create a new Approver with the provided message
    pub fn new(op_count: usize) -> Self {
        Self {
            op_count,
            state: TxSummaryApproverState::Init,
        }
    }

    /// Update [Approver] state, handling button events and returning the
    /// approval state on exit
    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<bool> {
        use ButtonEvent::*;
        use TxSummaryApproverState::*;

        match (self.state, btn) {
            // Transaction overview (first page)
            (Init, RightButtonRelease) => self.state = Op(0),

            // List of operations
            (Op(n), LeftButtonRelease) if n == 0 => self.state = Init,
            (Op(n), LeftButtonRelease) => self.state = Op(n - 1),
            (Op(n), RightButtonRelease) if n + 1 < self.op_count => self.state = Op(n + 1),
            (Op(_n), RightButtonRelease) => self.state = Fee,

            // Fee information
            (Fee, LeftButtonRelease) => self.state = Op(self.op_count - 1),
            (Fee, RightButtonRelease) => self.state = Allow,

            // Approve page
            (Allow, LeftButtonRelease) => self.state = Fee,
            (Allow, BothButtonsRelease) => return UiResult::Exit(true),
            (Allow, RightButtonRelease) => self.state = Deny,

            // Deny page
            (Deny, LeftButtonRelease) => self.state = Allow,
            (Deny, BothButtonsRelease) => return UiResult::Exit(false),

            // Both buttons pressed in other states cancels the request
            (_, BothButtonsRelease) => return UiResult::Exit(false),

            _ => return UiResult::None,
        }

        UiResult::Update
    }

    /// Render the [Approver] based on it's current internal state
    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, engine: &Engine<D, R>) {
        use TxSummaryApproverState::*;
        let mut title_buff = [0u8; 20];
        let mut value_buff = [0u8; 20];

        let mut buff = [0u8; 20];

        // Clear screen pre-render
        clear_screen();

        // Fetch transaction report
        let report = match engine.report() {
            Some(r) => r,
            None => {
                "NO SUMMARY AVAILABLE".place(Location::Middle, Layout::Centered, false);
                screen_util::screen_update();
                return;
            }
        };

        // Display arrows depending on page
        if self.state != Init {
            LEFT_ARROW.shift_v(0).display();
        }
        if self.state != Deny {
            RIGHT_ARROW.shift_v(0).display();
        }

        match self.state {
            Init => {
                ["Transaction", "Request"].place(Location::Middle, Layout::Centered, false);
            }
            Op(n) => {
                // Fetch balance change information
                let (kind, value) = report.balance_changes.index(n).unwrap();

                // Write value and token id
                // TODO: ensure values can not be concatenated

                let value_str = fmt_token_val(*value, kind.1, &mut value_buff);

                match &kind.0 {
                    // Balance changes
                    TransactionEntity::Ourself => {
                        let title_str = fmt_page("Balance", n, self.op_count, &mut title_buff);
                        [title_str, value_str].place(Location::Middle, Layout::Centered, false);
                    }
                    // Send value + address
                    TransactionEntity::Address(a) => {
                        let title_str = fmt_page("Send", n, self.op_count, &mut title_buff);
                        let addr_str = fmt_addr(a.as_ref(), &mut buff);

                        [title_str, value_str, addr_str].place(
                            Location::Middle,
                            Layout::Centered,
                            false,
                        );
                    }
                    // Swaps
                    TransactionEntity::Swap => {
                        let title_str = fmt_page("Swap", n, self.op_count, &mut buff);
                        [title_str, value_str].place(Location::Middle, Layout::Centered, false);
                    }
                }
            }
            // Fees
            Fee => {
                let value_str = fmt_token_val(
                    report.network_fee.value as i64,
                    report.network_fee.token_id,
                    &mut buff[..],
                );
                ["Fee", value_str].place(Location::Middle, Layout::Centered, false);
            }
            Deny => {
                tx_deny_page();
            }
            Allow => {
                tx_approve_page();
            }
        }

        screen_util::screen_update();
    }
}

fn fmt_page<'a>(name: &str, index: usize, total: usize, buff: &'a mut [u8]) -> &'a str {
    let n = match emstr::write!(&mut buff[..], name, "  (", index + 1, '/', total, ')') {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}

fn fmt_addr<'a>(addr: &[u8], buff: &'a mut [u8]) -> &'a str {
    let n = match emstr::write!(
        &mut buff[..],
        Hex(&addr[..4]),
        "...",
        Hex(&addr[addr.len() - 4..])
    ) {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}
