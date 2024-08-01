// Copyright (c) 2022-2023 The MobileCoin Foundation

use core::str::from_utf8;

use rand_core::{CryptoRng, RngCore};
use strum::{Display, EnumCount};

use emstr::{helpers::Hex, EncodeStr};

use ledger_secure_sdk_sys::buttons::ButtonEvent;

use ledger_device_sdk::ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::{
    engine::{Driver, Engine, TransactionEntity},
    helpers::{b58_encode_public_address, fmt_token_val},
};

use super::{
    clear_screen,
    helpers::{tx_approve_page, tx_deny_page},
    Address, UiResult,
};

/// UI Approval Element
///
/// Used for user-confirmation of key requests (and transactions, pending TxSummary availability)
#[derive(Clone, Debug, PartialEq)]
pub struct TxSummaryApprover {
    num_outputs: usize,
    num_totals: usize,
    state: TxSummaryApproverState,
    selected: bool,
    address: Option<Address<512>>,
}

#[derive(Copy, Clone, Debug, PartialEq, Display, EnumCount)]
enum TxSummaryApproverState {
    Init,
    Op(usize),
    Fee,
    Total(usize),
    Allow,
    Deny,
}

impl TxSummaryApprover {
    /// Create a new Approver with the provided message
    pub fn new(num_outputs: usize, num_totals: usize) -> Self {
        Self {
            num_outputs,
            num_totals,
            state: TxSummaryApproverState::Init,
            selected: false,
            address: None,
        }
    }

    /// Update [Approver] state, handling button events and returning the
    /// approval state on exit
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn update<D: Driver, R: RngCore + CryptoRng>(
        &mut self,
        btn: &ButtonEvent,
        engine: &Engine<D, R>,
    ) -> UiResult<bool> {
        use TxSummaryApproverState::*;

        match (self.state, btn) {
            // Transaction overview (first page)
            (Init, ButtonEvent::RightButtonRelease) => self.state = Op(0),

            // Passthrough to address renderer if available
            (Op(_), ButtonEvent::BothButtonsRelease) if self.address.is_some() => {
                self.address = None
            }
            (Op(_), _) if self.address.is_some() => {
                let address = self.address.as_mut().unwrap();
                address.update(btn).map_exit(|_| ());
            }

            // List of operations
            (Op(n), ButtonEvent::LeftButtonRelease) if n == 0 => self.state = Init,
            (Op(n), ButtonEvent::LeftButtonRelease) => self.state = Op(n - 1),
            (Op(n), ButtonEvent::RightButtonRelease) if n + 1 < self.num_outputs => {
                self.state = Op(n + 1)
            }
            (Op(_n), ButtonEvent::RightButtonRelease) => self.state = Fee,

            // Select for operations with addresses
            (Op(n), ButtonEvent::BothButtonsRelease) if self.address.is_none() => {
                let report = match engine.report() {
                    Some(r) => r,
                    None => return UiResult::None,
                };

                let h = match &report.outputs[n].0 {
                    TransactionEntity::OurAddress(h) => h,
                    TransactionEntity::OtherAddress(h) => h,
                    _ => return UiResult::None,
                };

                // Resolve address from short hash
                let s = match engine.address(h) {
                    Some(a) => a,
                    None => return UiResult::None,
                };

                // Setup address for rendering
                self.address = Some(Address::new(
                    &s.address,
                    s.fog_id,
                    s.fog_sig.as_ref().map(|s| s.as_slice()).unwrap_or(&[]),
                ));

                return UiResult::Update;
            }

            // Fee information
            (Fee, ButtonEvent::LeftButtonRelease) => self.state = Op(self.num_outputs - 1),
            (Fee, ButtonEvent::RightButtonRelease) => self.state = Total(0),

            // List of totals
            (Total(n), ButtonEvent::LeftButtonRelease) if n == 0 => self.state = Fee,
            (Total(n), ButtonEvent::LeftButtonRelease) => self.state = Total(n - 1),
            (Total(n), ButtonEvent::RightButtonRelease) if n + 1 < self.num_totals => {
                self.state = Total(n + 1)
            }
            (Total(_n), ButtonEvent::RightButtonRelease) => self.state = Allow,

            // Approve page
            (Allow, ButtonEvent::LeftButtonRelease) => self.state = Total(self.num_totals - 1),
            (Allow, ButtonEvent::BothButtonsRelease) => return UiResult::Exit(true),
            (Allow, ButtonEvent::RightButtonRelease) => self.state = Deny,

            // Deny page
            (Deny, ButtonEvent::LeftButtonRelease) => self.state = Allow,
            (Deny, ButtonEvent::BothButtonsRelease) => return UiResult::Exit(false),

            // Both buttons pressed in other states cancels the request
            (_, ButtonEvent::BothButtonsRelease) => return UiResult::Exit(false),

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
            Op(_n) if self.address.is_some() => {
                let address = self.address.as_ref().unwrap();
                address.render(engine);
            }
            Op(n) => {
                // Fetch balance change information
                let (entity, token_id, value) = &report.outputs[n];

                // Write value and token id
                // TODO: ensure values can not be concatenated

                let value_str = fmt_token_val(*value as i64, *token_id, &mut value_buff);

                match &entity {
                    // Balance changes to ourself or others
                    TransactionEntity::OurAddress(a) | TransactionEntity::OtherAddress(a) => {
                        // Switch heading depending on whether this is
                        // to an address we control
                        let heading = match &entity {
                            TransactionEntity::OurAddress(_) => "Receive",
                            TransactionEntity::OtherAddress(_) => "Send",
                            _ => unreachable!(),
                        };

                        DOWN_ARROW.shift_h(-60).shift_v(24).display();

                        let title_str = fmt_page(heading, n, self.num_outputs, &mut title_buff);

                        // Lookup address from cache
                        let addr_str = match engine.address(a) {
                            Some(c) => {
                                // Encode in b58 form for display
                                let b58 = b58_encode_public_address::<512>(
                                    &c.address,
                                    c.fog_id.url(),
                                    c.fog_sig.as_ref().map(|v| &v[..]).unwrap_or(&[]),
                                );

                                // Write to display string
                                match b58 {
                                    Ok(v) => fmt_b58_addr(&v, &mut buff),
                                    Err(_) => "B58 ENCODE ERROR",
                                }
                            }
                            // If we don't have a cache match, display short hash
                            // NOTE: this _shouldn't_ be possible so long
                            // as the cache size is the same as the report size
                            None => fmt_short_hash(a.as_ref(), &mut buff),
                        };

                        // Display title / value / address
                        [title_str, value_str, addr_str, ""].place(
                            Location::Middle,
                            Layout::Centered,
                            false,
                        );
                    }
                    // Swap outputs
                    TransactionEntity::Swap => {
                        let title_str = fmt_page("Swap", n, self.num_outputs, &mut buff);
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
            // Totals
            Total(n) => {
                // Fetch total information
                let (token_id, _total_kind, value) = &report.totals[n];

                let value_str = fmt_token_val(*value, *token_id, &mut value_buff);
                let title_str = fmt_page("Total", n, self.num_totals, &mut title_buff);
                [title_str, value_str].place(Location::Middle, Layout::Centered, false);
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

fn fmt_b58_addr<'a>(addr: &str, buff: &'a mut [u8]) -> &'a str {
    let n = match emstr::write!(&mut buff[..], &addr[..8], "...", &addr[addr.len() - 8..]) {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}

fn fmt_short_hash<'a>(addr: &[u8], buff: &'a mut [u8]) -> &'a str {
    let n = match emstr::write!(
        &mut buff[..],
        "(",
        Hex(&addr[..4]),
        "...",
        Hex(&addr[addr.len() - 4..]),
        ")"
    ) {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}
