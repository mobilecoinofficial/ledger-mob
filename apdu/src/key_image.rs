// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Key Image APDUs, used for key matching

use encdec::{Decode, Encode};
use mc_core::keys::TxOutPublic;
use mc_crypto_ring_signature::KeyImage;

use super::{ApduError, ApduStatic, Instruction, MOB_APDU_CLA};
use crate::helpers::{ki, pub_key};

/// Resolve a key image for a specific subaddress and `txout_public_key`
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
/// |                                                               |
/// /                        TXOUT_PUBLIC_KEY                       /
/// /                 (32-byte Ristretto Public Key)                /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct KeyImageReq {
    /// SLIP-0010 account index
    pub account_index: u32,
    /// Subkey index
    pub subaddress_index: u64,
    /// TX_OUT public key
    #[encdec(with = "pub_key")]
    pub txout_public_key: TxOutPublic,
}

impl KeyImageReq {
    /// Create a new application version APDU
    pub fn new(account_index: u32, subaddress_index: u64, txout_public_key: TxOutPublic) -> Self {
        Self {
            account_index,
            subaddress_index,
            txout_public_key,
        }
    }
}

impl ApduStatic for KeyImageReq {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::GetKeyImage as u8;
}

/// Key image response APDU
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
/// /                           KEY_IMAGE                           /
/// /               (32-byte compressed Ristretto point)            /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Copy, Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct KeyImageResp {
    /// SLIP-0010 account index
    pub account_index: u32,
    /// Subaddress index
    pub subaddress_index: u64,
    /// Key Image (compressed point)
    #[encdec(with = "ki")]
    pub key_image: KeyImage,
}

impl KeyImageResp {
    /// Create a new [`KeyImage`] APDU
    pub fn new(account_index: u32, subaddress_index: u64, key_image: KeyImage) -> Self {
        Self {
            account_index,
            subaddress_index,
            key_image,
        }
    }
}

#[cfg(test)]
mod test {
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_crypto_ring_signature::KeyImage;
    use mc_util_from_random::FromRandom;
    use rand::random;
    use rand_core::OsRng;

    use super::*;
    use crate::test::encode_decode_apdu;

    #[test]
    fn key_image_get_apdu() {
        let pub_key = RistrettoPublic::from(&RistrettoPrivate::from_random(&mut OsRng {}));

        let apdu = KeyImageReq::new(random(), random(), pub_key.into());

        let mut buff = [0u8; 128];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn key_image_ans_apdu() {
        let key_image = KeyImage::from(&RistrettoPrivate::from_random(&mut OsRng {}));

        let apdu = KeyImageResp::new(random(), random(), key_image);

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }
}
