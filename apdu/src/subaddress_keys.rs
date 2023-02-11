// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Subaddress related APDUs, for fetching / checking wallet subaddresses
//!

use encdec::{Decode, Encode};

use mc_core::keys::{SubaddressSpendPublic, SubaddressViewPrivate};

use super::{ApduError, ApduStatic, Instruction, MOB_APDU_CLA};
use crate::helpers::*;

/// Request keys for a given account index and subaddress
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         WALLET_INDEX                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       SUBADDRESS_INDEX                        |
/// |                           (8-bytes)                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Copy, Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct SubaddressKeyReq {
    /// SLIP-0010 account index
    pub account_index: u32,
    /// Subkey index
    pub subaddress_index: u64,
}

impl SubaddressKeyReq {
    /// Create a new [SubaddressKeyReq] APDU
    pub fn new(account_index: u32, subaddress_index: u64) -> Self {
        Self {
            account_index,
            subaddress_index,
        }
    }
}

impl ApduStatic for SubaddressKeyReq {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::GetSubaddressKeys as u8;
}

/// Subaddress key response
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         WALLET_INDEX                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       SUBADDRESS_INDEX                        |
/// |                         (8-byte u64)                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                    SUBADDR_VIEW_PRIVATE_KEY                   /
/// /                (32-byte Ristretto Private Key)                /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                    SUBADDR_SPEND_PUBLIC_KEY                   /
/// /                 (32-byte Ristretto Public Key)                /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct SubaddressKeyResp {
    /// SLIP-0010 account index
    pub account_index: u32,
    /// Subaddress index
    pub subaddress_index: u64,
    /// Vew Private Key
    #[encdec(with = "pri_key")]
    pub view_private: SubaddressViewPrivate,
    /// Spend public key
    #[encdec(with = "pub_key")]
    pub spend_public: SubaddressSpendPublic,
}

impl SubaddressKeyResp {
    /// Create a new [`SubaddressKeyResp`] APDU
    pub fn new(
        account_index: u32,
        subaddress_index: u64,
        view_private: SubaddressViewPrivate,
        spend_public: SubaddressSpendPublic,
    ) -> Self {
        Self {
            account_index,
            subaddress_index,
            view_private,
            spend_public,
        }
    }
}

#[cfg(test)]
mod test {
    use mc_crypto_keys::RistrettoPrivate;
    use rand::{random, rngs::OsRng};

    use mc_core::keys::{SubaddressSpendPrivate, SubaddressSpendPublic, SubaddressViewPrivate};
    use mc_util_from_random::FromRandom;

    use super::*;
    use crate::test::encode_decode_apdu;

    #[test]
    fn subaddress_keys_get_apdu() {
        let apdu = SubaddressKeyReq::new(random(), random());

        let mut buff = [0u8; 128];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn subaddress_keys_ans_apdu() {
        let view_private = SubaddressViewPrivate::from(RistrettoPrivate::from_random(&mut OsRng));
        let spend_private = SubaddressSpendPrivate::from(RistrettoPrivate::from_random(&mut OsRng));

        let apdu = SubaddressKeyResp::new(
            random(),
            random(),
            view_private,
            SubaddressSpendPublic::from(&spend_private),
        );

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }
}
