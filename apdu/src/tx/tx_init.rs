// Copyright (c) 2022-2023 The MobileCoin Foundation

use encdec::{Decode, Encode};
use ledger_apdu::ApduStatic;

use mc_core::keys::Key;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

use crate::{helpers::*, ApduError, Instruction, MOB_APDU_CLA};

/// Marker trait for onetime key type (to be moved to `mc_core_types`)
#[derive(Copy, Clone, PartialEq, Default, Debug)]
pub struct TxOnetime;

/// Transaction onetime key type (to be moved to `mc_core_types`)
pub type TxOnetimeKey = Key<TxOnetime, TxOnetime, RistrettoPrivate>;

/// Marker trait for transaction key type (to be moved to `mc_core_types`)
#[derive(Copy, Clone, PartialEq, Default, Debug)]
pub struct Tx;

/// Transaction public key type (to be moved to `mc_core_types`)
pub type TxPublicKey = Key<Tx, Tx, RistrettoPublic>;

/// Transaction private key type (to be moved to `mc_core_types`)
pub type TxPrivateKey = Key<Tx, Tx, RistrettoPrivate>;

/// Transaction initialisation APDU, sets up a transaction for execution
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   NUM_RINGS   |                    RESERVED                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        ACCOUNT_INDEX                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           TOKEN_ID                            |
/// |                        (u64, 8-byte)                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxInit {
    /// Number of rings to be signed
    pub num_rings: u8,

    /// Reserved for future use (maintains 32-bit field alignment)
    #[encdec(with = "arr")]
    reserved: [u8; 3],

    /// Account index for SLIP-010 derivation
    pub account_index: u32,
}

impl ApduStatic for TxInit {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxInit as u8;
}

impl TxInit {
    /// Create a new [`TxInit`] request
    pub fn new(account_index: u32, num_rings: u8) -> Self {
        Self {
            num_rings,
            reserved: [0u8; 3],
            account_index,
        }
    }
}

/// Set the message for the transaction
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  MESSAGE_LEN  |                    RESERVED                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                            MESSAGE                            /
/// /                       (variable length)                       /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug)]
pub struct TxSetMessage<'a> {
    /// `Message` for transaction, derived from prefix
    pub message: &'a [u8],
}

impl<'a> ApduStatic for TxSetMessage<'a> {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxSetMessage as u8;
}

impl<'a> TxSetMessage<'a> {
    pub fn new(message: &'a [u8]) -> Self {
        Self { message }
    }

    /// Compute hash of [TxSetMessage] object
    pub fn hash(&self) -> [u8; 32] {
        crate::digest::digest_tx_set_message(self.message)
    }
}

impl<'a> Encode for TxSetMessage<'a> {
    type Error = ApduError;

    /// Encode an [`TxSetMessage`] APDU into the provided buffer
    #[inline]
    fn encode(&self, buff: &mut [u8]) -> Result<usize, ApduError> {
        let d = self.message;

        if buff.len() < d.len() + 1 {
            return Err(ApduError::InvalidLength);
        }

        let mut index = 0;
        buff[index] = d.len() as u8;
        index += 4;

        buff[index..][..d.len()].copy_from_slice(d);
        index += d.len();

        Ok(index)
    }

    #[inline]
    fn encode_len(&self) -> Result<usize, ApduError> {
        Ok(1 + self.message.len())
    }
}

impl<'a> Decode<'a> for TxSetMessage<'a> {
    type Output = Self;
    type Error = ApduError;

    /// Decode a [`TxSetMessage`] APDU from the provided buffer
    #[inline]
    fn decode(buff: &'a [u8]) -> Result<(Self, usize), ApduError> {
        let mut index = 0;

        let l = buff[index] as usize;
        index += 4;

        let message = &buff[index..][..l];
        index += l;

        Ok((Self { message }, index))
    }
}

#[cfg(test)]
mod test {
    use rand::random;

    use super::TxInit;
    use crate::test::encode_decode_apdu;

    #[test]
    fn encode_decode_txinit() {
        let apdu = TxInit::new(random(), random());

        let mut buff = [0u8; 256];
        let _n = encode_decode_apdu(&mut buff, &apdu);

        //assert_eq!(n, 48);
    }
}
