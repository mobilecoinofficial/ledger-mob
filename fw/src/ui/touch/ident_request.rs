// Copyright (c) 2022-2026 The MobileCoin Foundation

//! SLIP-0017 identity challenge approval page for touch devices.
//!
//! NOTE:  this is a _blocking_ review, so the app stops serving
//! APDUs while the user decides. See `DeviceHandle::identity` for the
//! host-side handling of this.

use emstr::{helpers::Hex, EncodeStr};
use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::nbgl::{Field, NbglReview, TransactionType};

use ledger_mob_core::engine::{Driver, Engine};

/// Hex encoded challenge length (matches `Ident::challenge`, a `Vec<u8, 64>`)
const CHALLENGE_HEX_LEN: usize = 64 * 2;

/// Identity challenge review page
pub struct IdentRequest {
    review: NbglReview<'static>,
}

impl IdentRequest {
    pub fn new() -> Self {
        let review = NbglReview::new()
            .glyph(&crate::consts::MOB64X64)
            .tx_type(TransactionType::Message)
            .titles("Review identity request", "", "Sign identity challenge");

        Self { review }
    }

    /// Show the (blocking) identity review, returning the user decision
    ///
    /// Returns [None] where no identity request is pending, in which case
    /// nothing is displayed and the caller must not apply a decision.
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn show_blocking<D: Driver, R: RngCore + CryptoRng>(
        &self,
        engine: &Engine<D, R>,
    ) -> Option<bool> {
        // NOTE: the engine only returns this while the request is pending,
        // so the challenge must be read _prior_ to applying the decision
        let ident = engine.ident()?;

        // NOTE: must be declared before `fields`, which borrows from it
        let mut challenge_buff = [0u8; CHALLENGE_HEX_LEN];

        let fields = [
            Field {
                name: "URI",
                value: c_safe(ident.uri()),
            },
            Field {
                name: "Challenge",
                value: fmt_hex(ident.challenge(), &mut challenge_buff),
            },
        ];

        Some(self.review.show(&fields))
    }
}

/// Truncate a host provided string at the first NUL
///
/// Required as NBGL page text is converted to `CString`s, which panics
/// on strings containing interior NULs.
fn c_safe(v: &str) -> &str {
    match v.split('\0').next() {
        Some(v) => v,
        None => "",
    }
}

/// Hex encode a value into the provided buffer for display
fn fmt_hex<'a>(value: &[u8], buff: &'a mut [u8]) -> &'a str {
    let n = match emstr::write!(&mut buff[..], Hex(value)) {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match core::str::from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}
