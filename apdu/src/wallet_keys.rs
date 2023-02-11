// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Wallet key APDUs, for fetching root account keys

use encdec::{Decode, Encode};

use mc_core::keys::{RootSpendPublic, RootViewPrivate};

use super::{ApduError, ApduStatic, Instruction, MOB_APDU_CLA};
use crate::helpers::*;

/// Wallet key request APDU.
///
/// Requests root / account keys for SLIP-0010 derived account.
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         WALLET_INDEX                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Copy, Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct WalletKeyReq {
    /// SLIP-0010 account index
    pub account_index: u32,
}

impl WalletKeyReq {
    /// Create a new [WalletKeyReq] APDU
    pub fn new(account_index: u32) -> Self {
        Self { account_index }
    }
}

impl ApduStatic for WalletKeyReq {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::GetWalletKeys as u8;
}

/// Wallet key response APDU
///
/// Contains root view private and spend public keys for application use.
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
/// /                      ROOT_VIEW_PRIVATE_KEY                    /
/// /                (32-byte Ristretto Private Key)                /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                      ROOT_SPEND_PUBLIC_KEY                    /
/// /                 (32-byte Ristretto Public Key)                /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct WalletKeyResp {
    /// SLIP-0010 account index
    pub account_index: u32,
    /// View Private Key
    #[encdec(with = "pri_key")]
    pub view_private: RootViewPrivate,
    /// Spend public key
    #[encdec(with = "pub_key")]
    pub spend_public: RootSpendPublic,
}

impl WalletKeyResp {
    /// Create a new [`WalletKeyResp`] APDU
    pub fn new(
        account_index: u32,
        view_private: RootViewPrivate,
        spend_public: RootSpendPublic,
    ) -> Self {
        Self {
            account_index,
            view_private,
            spend_public,
        }
    }
}

#[cfg(test)]
mod test {

    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

    use mc_util_from_random::FromRandom;

    use rand::random;
    use rand_core::OsRng;

    use super::*;
    use crate::test::encode_decode_apdu;

    #[test]
    fn wallet_keys_get_apdu() {
        let apdu = WalletKeyReq::new(random());

        let mut buff = [0u8; 128];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn wallet_keys_ans_apdu() {
        let (view_private, spend_private) = (
            RistrettoPrivate::from_random(&mut OsRng {}),
            RistrettoPrivate::from_random(&mut OsRng {}),
        );

        let apdu = WalletKeyResp::new(
            random(),
            view_private.into(),
            RistrettoPublic::from(&spend_private).into(),
        );

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }
}
