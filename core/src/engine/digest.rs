// Copyright (c) 2022-2023 The MobileCoin Foundation

use encdec::{DecodeOwned, Encode};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512_256};

use super::Event;

/// Transaction digest, used to keep a running digest of inputs to
/// the transaction engine to ensure sync between the host and hardware
/// wallet.
#[derive(Clone, PartialEq, Encode)]
pub struct TxDigest([u8; 32]);

impl core::fmt::Debug for TxDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0[..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::Display for TxDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0[..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl DecodeOwned for TxDigest {
    type Output = TxDigest;

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

impl TxDigest {
    /// Create a new (empty) transaction digest
    pub const fn new() -> Self {
        Self([0u8; 32])
    }

    /// Reset transaction digest with from random seed
    pub fn from_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);

        let r = Sha512_256::new().chain_update(b).finalize();
        b.copy_from_slice(r.as_ref());

        TxDigest(b)
    }

    /// Update transaction digest with new event
    // TODO: what if we apply an event but lose the response, will the client retry..?
    // TODO: swap to tree approach, cache prior event and skip updates to allow retries
    // TODO: could use [Digestible], though this adds dependencies for implementers?
    pub fn update(&mut self, evt: &Event<'_>) -> &Self {
        // Build and update digest
        let mut d = Sha512_256::new();

        // Prior state
        d.update(self.0);

        // New event
        d.update(evt.digest());

        // Write to internal state
        self.0.copy_from_slice(d.finalize().as_ref());

        self
    }
}
