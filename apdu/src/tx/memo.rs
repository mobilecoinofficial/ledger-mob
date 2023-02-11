// Copyright (c) 2022-2023 The MobileCoin Foundation

use encdec::{Decode, Encode};
use mc_core::{
    account::RingCtAddress,
    keys::{SubaddressViewPublic, TxOutPublic},
};

use super::TxState;
use crate::{
    digest::digest_tx_sign_memo, helpers::*, state::Digest, ApduError, ApduStatic, Instruction,
    MOB_APDU_CLA,
};

const MEMO_PAYLOAD_NO_HMAC: usize = 48;
const MEMO_HMAC_LEN: usize = 16;

/// Memo HMAC signing request
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          MEMO_KIND            |  PAYLOAD_LEN  |   RESERVED    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                        SUBADDRESS_INDEX                       /
/// /               (u64 subaddress for memo signing)               /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                         TX_PUBLIC_KEY                         /
/// /                (32-byte Ristretto Public Key)                 /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                     TARGET_VIEW_PUBLIC_KEY                    /
/// /                 (32-byte Ristretto Public Key)                /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                           PAYLOAD                             /
/// /                      (48-byte memo body)                      /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxMemoSign {
    /// Memo type
    #[encdec(with = "arr")]
    pub kind: [u8; 2],

    /// Payload length, always 48 bytes (included for future expansion)
    pub payload_len: u8,

    /// Reserved for future use, must be 0 (ensures 32-bit alignment)
    pub reserved: u8,

    /// Signing subaddress index
    pub subaddress_index: u64,

    /// TxOut public key
    #[encdec(with = "pub_key")]
    pub tx_public_key: TxOutPublic,

    /// Target view public subaddress
    #[encdec(with = "pub_key")]
    pub target_view_public: SubaddressViewPublic,

    /// Memo payload
    #[encdec(with = "arr")]
    pub payload: [u8; MEMO_PAYLOAD_NO_HMAC],
}

impl ApduStatic for TxMemoSign {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxMemoSign as u8;
}

impl TxMemoSign {
    /// Create a new memo signing request with the provided target, kind, and payload
    pub fn new<T: RingCtAddress>(
        subaddress_index: u64,
        tx_public_key: TxOutPublic,
        target: &T,
        kind: [u8; 2],
        payload: [u8; MEMO_PAYLOAD_NO_HMAC],
    ) -> Self {
        Self {
            subaddress_index,
            kind,
            payload_len: MEMO_PAYLOAD_NO_HMAC as u8,
            reserved: 0,
            tx_public_key,
            target_view_public: target.view_public_key(),
            payload,
        }
    }

    /// Compute hash for [TxMemoSign] object
    pub fn hash(&self) -> [u8; 32] {
        digest_tx_sign_memo(
            &self.subaddress_index,
            &self.tx_public_key,
            &self.target_view_public,
            &self.kind,
            &self.payload,
        )
    }
}

/// Memo signature response
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            TX_STATE           |             VALUE             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           TX_DIGEST                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                           MEMO_HMAC                           |
/// |                        (16-byte HMAC)                         |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxMemoSig {
    /// Current transaction engine state
    pub state: TxState,
    /// Value associated with current state (zero otherwise)
    pub value: u16,
    /// Transaction state digest
    pub digest: Digest,

    /// Memo HMAC
    // TODO: add an HMAC type in mc_core
    #[encdec(with = "arr")]
    pub hmac: [u8; MEMO_HMAC_LEN],
}

impl TxMemoSig {
    /// Create a new memo signature response
    pub fn new(state: TxState, value: u16, digest: Digest, hmac: [u8; MEMO_HMAC_LEN]) -> Self {
        Self {
            state,
            value,
            digest,
            hmac,
        }
    }
}

#[cfg(test)]
mod test {
    use rand::rngs::OsRng;

    use mc_core::{account::Account, consts::DEFAULT_SUBADDRESS_INDEX, subaddress::Subaddress};
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;

    use super::*;
    use crate::test::encode_decode_apdu;

    use rand_core::RngCore;

    #[test]
    fn encode_decode_memo_sign_req() {
        let (transaction_private, view_private, spend_private) = (
            RistrettoPrivate::from_random(&mut OsRng {}),
            RistrettoPrivate::from_random(&mut OsRng {}),
            RistrettoPrivate::from_random(&mut OsRng {}),
        );

        let target = Account::new(view_private.into(), spend_private.into());
        let target_subaddr = target.subaddress(0);

        let mut payload = [0u8; MEMO_PAYLOAD_NO_HMAC];
        OsRng {}.fill_bytes(&mut payload);

        let apdu = TxMemoSign::new(
            DEFAULT_SUBADDRESS_INDEX,
            RistrettoPublic::from(&transaction_private).into(),
            &target_subaddr,
            [0, 1],
            payload,
        );

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);

        // TODO: check values in buffer
    }

    #[test]
    fn encode_decode_memo_sig_resp() {
        let mut hmac = [0u8; MEMO_HMAC_LEN];
        OsRng {}.fill_bytes(&mut hmac);

        let apdu = TxMemoSig::new(
            TxState::SignMemos,
            0u16,
            Digest::from_random(&mut OsRng {}),
            hmac,
        );

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }
}
