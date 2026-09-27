// Copyright (c) 2022-2026 The MobileCoin Foundation

//! Transaction summary approval flow for touch (NBGL) devices.
//!
//! Streams the transaction report over one page per output, the network fee,
//! then one page per token total, mirroring the page order of the nano
//! approver in `crate::ui::nano::tx_summary_approver`.
//!
//! [`NbglStreamingReview`] is used rather than a single `NbglReview` field list
//! because a summary carries up to `MAX_RECORDS` (16) outputs, each with a b58
//! address of up to [`B58_MAX_LEN`] bytes. Streaming keeps only the page being
//! displayed resident, so a 16 output summary costs the same heap as a single
//! output one.
//!
//! NOTE: this is a _blocking_ review, so the app stops serving APDUs while the
//! user pages through it. The host tolerates this: `await_approval` treats a
//! timed out `TxInfo` as "keep waiting" and retries.

use heapless::String;
use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::nbgl::{
    Field, NbglStreamingReview, NbglStreamingReviewStatus, TransactionType,
};

use ledger_mob_core::{
    engine::{Driver, Engine, TransactionEntity},
    helpers::{b58_encode_public_address, fmt_token_val},
};

use crate::ui::{fmt_page, fmt_short_hash};

/// Maximum b58 encoded address length (matches `B58_MAX_LEN` in `ledger-mob-core`)
const B58_MAX_LEN: usize = 512;

/// Title shown on the first page of the review
const TITLE: &str = "Review MobileCoin transaction";

/// Title shown on the final (confirmation) page of the review
const FINISH_TITLE: &str = "Sign MobileCoin transaction?";

/// Transaction summary review
pub struct TxSummaryRequest {
    review: NbglStreamingReview,

    /// Number of outputs in the report, used for page numbering
    num_outputs: usize,

    /// Number of token totals in the report, used for page numbering
    num_totals: usize,

    /// Scratch for the b58 address of the page being shown, reused per page.
    ///
    /// NOTE: held here rather than on the stack as `Ui` lives in the static
    /// `APP_CTX` and the OS stack budget is small (see `main.rs`).
    addr: String<B58_MAX_LEN>,
}

impl TxSummaryRequest {
    /// Create a new [TxSummaryRequest] for a report with the given shape
    pub fn new(num_outputs: usize, num_totals: usize) -> Self {
        let review = NbglStreamingReview::new()
            .tx_type(TransactionType::Transaction)
            .glyph(&crate::consts::MOB64X64);

        Self {
            review,
            num_outputs,
            num_totals,
            addr: String::new(),
        }
    }

    /// Show the (blocking) summary review, returning the user decision.
    ///
    /// Returns [None] where no report is available, in which case nothing is
    /// displayed and the caller must decide what to do with the request.
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn show_blocking<D: Driver, R: RngCore + CryptoRng>(
        &mut self,
        engine: &Engine<D, R>,
    ) -> Option<bool> {
        // NOTE: the report is only available while the summarizer is live, so
        // this must be read _prior_ to applying the decision
        let report = engine.report()?;

        // Show the introduction page, which can be rejected directly
        if !self.review.start(TITLE, None) {
            return Some(false);
        }

        // One page per output
        let num_outputs = self.num_outputs.min(report.outputs.len());
        for n in 0..num_outputs {
            let (entity, token_id, value) = &report.outputs[n];

            // NOTE: these must be declared before `fields`, which borrows them
            let mut title_buff = [0u8; 24];
            let mut value_buff = [0u8; 32];
            let mut hash_buff = [0u8; 24];

            let value_str = fmt_token_val(*value as i128, *token_id, &mut value_buff);

            // Switch heading depending on whether this is an address we control
            let (heading, hash) = match entity {
                TransactionEntity::OurAddress(h) => ("Receive", Some(h)),
                TransactionEntity::OtherAddress(h) => ("Send", Some(h)),
                TransactionEntity::Swap => ("Swap", None),
            };

            let title_str = fmt_page(heading, n, num_outputs, &mut title_buff);

            // Resolve the destination address from the summarizer cache,
            // displaying the short hash where this is not available.
            // NOTE: this _shouldn't_ be possible so long as the cache size is
            // the same as the report size.
            let addr_str = match hash {
                Some(h) => match engine.address(h) {
                    Some(a) => {
                        self.addr = match b58_encode_public_address::<B58_MAX_LEN>(
                            &a.address,
                            a.fog_id.url(),
                            a.fog_sig.as_ref().map(|s| s.as_slice()).unwrap_or(&[]),
                        ) {
                            Ok(v) => v,
                            Err(_e) => {
                                let mut s = String::new();
                                let _ = s.push_str("B58 ENCODE ERROR");
                                s
                            }
                        };

                        Some(self.addr.as_str())
                    }
                    None => Some(fmt_short_hash(h.as_ref(), &mut hash_buff)),
                },
                None => None,
            };

            let title = Field {
                name: title_str,
                value: value_str,
            };

            let r = match addr_str {
                Some(v) => self.next(&[
                    title,
                    Field {
                        name: "To",
                        value: v,
                    },
                ]),
                None => self.next(&[title]),
            };

            if let Some(v) = r {
                return Some(v);
            }
        }

        // Network fee
        {
            let mut value_buff = [0u8; 32];

            let fields = [Field {
                name: "Fee",
                value: fmt_token_val(
                    report.network_fee.value as i128,
                    report.network_fee.token_id,
                    &mut value_buff,
                ),
            }];

            if let Some(v) = self.next(&fields) {
                return Some(v);
            }
        }

        // One page per token total
        let num_totals = self.num_totals.min(report.totals.len());
        for n in 0..num_totals {
            let (token_id, _total_kind, value) = &report.totals[n];

            let mut title_buff = [0u8; 24];
            let mut value_buff = [0u8; 32];

            let fields = [Field {
                name: fmt_page("Total", n, num_totals, &mut title_buff),
                value: fmt_token_val(*value, *token_id, &mut value_buff),
            }];

            if let Some(v) = self.next(&fields) {
                return Some(v);
            }
        }

        // Confirmation page
        Some(self.review.finish(FINISH_TITLE))
    }

    /// Advance the review, returning `Some(decision)` where the flow has ended
    /// and [None] where it should continue.
    fn next(&self, fields: &[Field]) -> Option<bool> {
        match self.review.next(fields) {
            NbglStreamingReviewStatus::Next => None,
            // The review is not skippable so `Skipped` should be unreachable,
            // treat it as a rejection rather than shortcutting the review
            NbglStreamingReviewStatus::Rejected | NbglStreamingReviewStatus::Skipped => Some(false),
        }
    }
}
