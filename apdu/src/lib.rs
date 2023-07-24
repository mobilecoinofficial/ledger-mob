// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Protocol / APDU definitions for MobileCoin app communication
//!
//! This module provides a protocol specification and reference implementation for communication
//! with MobileCoin wallets.
//!
//! APDUs use a primitive binary encoding to simplify implementation with unsupported languages and platforms
//! (as well as due to inconvenient incompatibilities with prost/heapless/no_std/no_alloc that preclude the direct use of
//!  existing protobuf encodings, if this is resolved in future we _may_ be able to share the standard protocols)
//!
//! Encodings are intended to be _roughly_ equivalent to packed c structures while maintaining
//! 32-bit field alignment to reduce the need for unaligned access on constrained platforms.
//! All field encodings are little-endian, because most of the world is these days.
//!
//!

#![no_std]

use core::fmt::Debug;

pub use ledger_proto::{ApduError, ApduReq, ApduStatic};

pub mod app_info;
pub mod digest;
pub mod ident;
pub mod key_image;
pub mod prelude;
pub mod random;
pub mod state;
pub mod subaddress_keys;
pub mod tx;
pub mod wallet_keys;

mod helpers;

/// MobileCoin APDU Class
pub const MOB_APDU_CLA: u8 = 0xab;

pub const MOB_PROTO_VERSION: u8 = 0x01;

/// MobileCoin APDU instruction codes
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum Instruction {
    // General instructions
    GetAppInfo = 0x00,

    // Mobilecoin instructions
    /// Fetch wallet keys
    GetWalletKeys = 0x10,

    /// Fetch keys for a specific subaddress
    GetSubaddressKeys = 0x11,

    /// Request a key image
    GetKeyImage = 0x12,

    /// Fetch a random value
    GetRandom = 0x13,

    /// Issue SLIP-0017 ED25519 identity request
    IdentSignReq = 0x14,

    /// Fetched signed identity following approval
    IdentGetReq = 0x15,

    /// Initialise a transaction
    TxInit = 0x20,

    /// Sign a memo
    TxMemoSign = 0x21,

    /// Set message for signing
    TxSetMessage = 0x22,

    /// Start building TX summary
    TxSummaryInit = 0x30,

    /// Add TxOut to summary
    TxSummaryAddTxOut = 0x31,

    /// Add TxOut unblinding to summary
    TxSummaryAddTxOutUnblinding = 0x32,

    /// Add TxIn to summary
    TxSummaryAddTxIn = 0x33,

    /// Build Tx summary
    TxSummaryBuild = 0x34,

    /// Start a ring signing operation
    TxRingInit = 0x40,

    /// Set blinding factors
    TxSetBlinding = 0x41,

    /// Add TxOuts to ring
    TxAddTxOut = 0x42,

    /// Sign ring
    TxSign = 0x43,

    /// Fetch key image for a signed ring
    TxGetKeyImage = 0x44,

    /// Fetch a response for a given ring entry in the signed ring
    TxGetResponse = 0x45,

    /// Complete a transaction
    TxComplete = 0x50,

    /// Fetch transaction state
    TxGetInfo = 0x51,
}

/// Helper macro for encoding `bitflags` types
#[macro_export]
macro_rules! encdec_bitflags {
    ($b:ty) => {
        impl encdec::Encode for $b {
            type Error = ApduError;

            fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
                let bits: u8 = self.bits();
                encdec::Encode::encode(&bits, buff).map_err(|e| e.into())
            }

            fn encode_len(&self) -> Result<usize, Self::Error> {
                let bits: u8 = self.bits();
                encdec::Encode::encode_len(&bits).map_err(|e| e.into())
            }
        }

        impl encdec::DecodeOwned for $b {
            type Output = $b;
            type Error = ApduError;

            fn decode_owned(buff: &[u8]) -> Result<(Self, usize), Self::Error> {
                let v = <$b>::from_bits_truncate(buff[0]);
                Ok((v, 1))
            }
        }
    };
}

#[cfg(test)]
pub(crate) mod test {
    use encdec::EncDec;

    use super::*;

    /// Helper for APDU encode / decode tests
    pub fn encode_decode_apdu<'a, A: EncDec<'a, ApduError> + PartialEq>(
        buff: &'a mut [u8],
        apdu: &A,
    ) -> usize {
        // Encode APDU
        let n = apdu.encode(buff).expect("encode failed");

        // Ensure encoded data fits maximum APDU payload
        let m = 249;
        assert!(n < m, "encoded length {n} exceeds maximum APDU payload {m}");

        // Check encoded length matches expected length
        let expected_n = apdu.encode_len().expect("get length failed");
        assert_eq!(n, expected_n, "encode length mismatch");

        // Decode APDU
        let (decoded, decoded_n) = A::decode(&buff[..n]).expect("decode failed");

        // Check decoded object and length match
        assert_eq!(apdu, &decoded);
        assert_eq!(expected_n, decoded_n);

        // Return length, useful for rough confirmation of packing expectations
        n
    }
}
