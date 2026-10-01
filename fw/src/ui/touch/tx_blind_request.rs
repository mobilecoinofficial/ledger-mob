// Copyright (c) 2022-2026 The MobileCoin Foundation

//! Blind transaction approval screen for touch (NBGL) devices.

use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::nbgl::{Field, NbglReview, TransactionType};

use ledger_mob_core::engine::{Driver, Engine};

use crate::ui::to_hex_str;

/// Length of the hex encoded 32-byte transaction digest
const DIGEST_HEX_LEN: usize = 64;

/// UI blind approval element
///
/// Used for confirming transactions where no summary is available.
pub struct TxBlindRequest;

impl Default for TxBlindRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl TxBlindRequest {
    /// Create a new [TxBlindRequest]
    pub fn new() -> Self {
        Self
    }

    /// Show the blind signing review, blocking until the user approves or
    /// rejects, and returning their choice.
    pub fn show_blocking<D: Driver, R: RngCore + CryptoRng>(&self, engine: &Engine<D, R>) -> bool {
        // Encode the signing digest for display.
        //
        // NOTE: this buffer must outlive the `show` call below as `Field` borrows its value
        let mut buff = [0u8; DIGEST_HEX_LEN];
        let hash = match engine.message() {
            Some(m) => to_hex_str(m, &mut buff).unwrap_or("ENCODE ERROR"),
            None => "NO MESSAGE",
        };

        NbglReview::new()
            .blind()
            .tx_type(TransactionType::Transaction)
            .glyph(&crate::consts::MOB64X64)
            .titles(
                "Review MobileCoin transaction",
                "No transaction summary is available, verify the hash matches your wallet",
                "Sign MobileCoin transaction?",
            )
            .show(&[Field {
                name: "Transaction hash",
                value: hash,
            }])
    }
}
