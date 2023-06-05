// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Application State APDUs
//!

use encdec::{DecodeOwned, Encode};
use ledger_proto::ApduError;
use num_enum::TryFromPrimitive;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha512_256};
use strum::{Display, EnumIter, EnumString, EnumVariantNames};

/// Engine state enumeration
/// used in [`TxInfo`] to communicate transaction progress
#[derive(
    Copy, Clone, PartialEq, Debug, EnumString, Display, EnumVariantNames, EnumIter, TryFromPrimitive,
)]
#[repr(u8)]
pub enum TxState {
    Init = 0x00,
    SignMemos = 0x01,
    SetMessage = 0x02,
    SummaryInit = 0x03,
    SummaryAddTxOut = 0x04,
    SummaryAddTxIn = 0x05,
    SummaryReady = 0x06,
    SummaryComplete = 0x07,
    Pending = 0x10,
    Ready = 0x20,
    RingInit = 0x30,
    RingBuild = 0x31,
    RingSign = 0x32,
    RingComplete = 0x33,
    TxComplete = 0x40,
    TxDenied = 0x41,
    IdentPending = 0x50,
    IdentApproved = 0x51,
    IdentDenied = 0x52,
    Error = 0xFF,
}

impl Encode for TxState {
    type Error = ApduError;

    fn encode_len(&self) -> Result<usize, ApduError> {
        Ok(1)
    }

    fn encode(&self, buff: &mut [u8]) -> Result<usize, ApduError> {
        buff[0] = *self as u8;
        Ok(1)
    }
}

impl DecodeOwned for TxState {
    type Output = Self;

    type Error = ApduError;

    fn decode_owned(buff: &[u8]) -> Result<(Self::Output, usize), ApduError> {
        if buff.is_empty() {
            return Err(ApduError::InvalidLength);
        }

        match Self::try_from(buff[0]) {
            Ok(v) => Ok((v, 1)),
            Err(_) => Err(ApduError::InvalidEncoding),
        }
    }
}

/// Transaction digest, used to keep a running digest of inputs to
/// the transaction engine to ensure sync between the host and hardware
/// wallet.
#[derive(Clone, PartialEq, Encode)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Create a new (empty) state digest
    pub const fn new() -> Self {
        Self([0u8; 32])
    }

    /// Reset state digest from random seed
    #[inline(never)]
    pub fn from_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);

        let r = Sha512_256::new().chain_update(b).finalize();
        b.copy_from_slice(r.as_ref());

        Self(b)
    }

    /// Update transaction digest with new event
    // TODO: what if we apply an event but lose the response, will the client retry..?
    // TODO: swap to tree approach, cache prior event and skip updates to allow retries
    // TODO: could use [Digestible], though this adds dependencies for implementers?
    #[inline(never)]
    pub fn update(&mut self, evt: &[u8; 32]) -> &Self {
        // Build and update digest
        let mut d = Sha512_256::new();

        // Prior state
        d.update(self.0);

        // New event
        d.update(evt);

        // Write to internal state
        self.0.copy_from_slice(d.finalize().as_ref());

        self
    }
}

/// Debug format [Digest] as hex
impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0[..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Display [Digest] as hex
impl core::fmt::Display for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0[..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Decode [Digest] into owned array
impl DecodeOwned for Digest {
    type Output = Digest;

    type Error = encdec::Error;

    fn decode_owned(buff: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        if buff.len() < 32 {
            return Err(encdec::Error::Length);
        }

        let mut d = [0u8; 32];
        d.copy_from_slice(&buff[..32]);
        Ok((Self(d), 32))
    }
}
