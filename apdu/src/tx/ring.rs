// Copyright (c) 2022-2023 The MobileCoin Foundation

use curve25519_dalek::ristretto::CompressedRistretto;
use encdec::{Decode, Encode};

use ledger_apdu::ApduStatic;

use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature::{CompressedCommitment, KeyImage, ReducedTxOut, Scalar};

use crate::{
    digest::{digest_ring_add_txout, digest_ring_init, digest_ring_set_blinding, digest_ring_sign},
    helpers::*,
    ApduError, Instruction, MOB_APDU_CLA,
};

/// Start a ring signing operation
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   RING_SIZE   |  REAL_INDEX   |           RESERVED            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       SUBADDRESS_INDEX                        |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            VALUE                              |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxRingInit {
    /// Size of ring to be signed
    pub ring_size: u8,

    /// Index of real tx_in in ring
    pub real_index: u8,

    /// Reserved for future use (ensures next field alignment)
    #[encdec(with = "arr")]
    reserved: [u8; 2],

    /// Subaddress of real tx_in, used for onetime_private_key recovery
    pub subaddress_index: u64,

    /// Ring value
    pub value: u64,

    /// Ring token_id
    pub token_id: u64,
}

impl ApduStatic for TxRingInit {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxRingInit as u8;
}

impl TxRingInit {
    /// Create a new ring initialisation request
    pub fn new(
        ring_size: u8,
        real_index: u8,
        subaddress_index: u64,
        value: u64,
        token_id: u64,
    ) -> Self {
        Self {
            ring_size,
            real_index,
            reserved: [0u8; 2],
            subaddress_index,
            value,
            token_id,
        }
    }

    /// Compute hash from [TxRingInit] object
    pub fn hash(&self) -> [u8; 32] {
        digest_ring_init(
            self.ring_size,
            self.real_index,
            &self.subaddress_index,
            &self.value,
            &self.token_id,
        )
    }
}

/// Set blinding for ring signing
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                            BLINDING                           /
/// /                   (32-byte Ristretto Scalar)                  /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                         OUTPUT_BLINDING                       /
/// /                   (32-byte Ristretto Scalar)                  /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxSetBlinding {
    #[encdec(with = "scalar")]
    pub blinding: Scalar,

    #[encdec(with = "scalar")]
    pub output_blinding: Scalar,
}

impl ApduStatic for TxSetBlinding {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxSetBlinding as u8;
}

impl TxSetBlinding {
    /// Crete a new [TxSetBlinding] object
    pub fn new(blinding: Scalar, output_blinding: Scalar) -> Self {
        Self {
            blinding,
            output_blinding,
        }
    }

    /// Compute hash from [TxSetBlinding] object
    pub fn hash(&self) -> [u8; 32] {
        digest_ring_set_blinding(&self.blinding, &self.output_blinding)
    }
}

/// Add a TxOut to a ring signing operation
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   RING_INDEX  |                  RESERVED                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                        TXOUT_PUBLIC_KEY                       /
/// /           (32-byte Compressed Ristretto Public Key)           /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                        TXOUT_TARGET_KEY                       /
/// /           (32-byte Compressed Ristretto Public Key)           /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                          COMMITMENT                           /
/// /             (32-byte Compressed Ristretto Point)              /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxAddTxOut {
    /// The tx_out index in the ring
    pub ring_index: u8,

    /// Reserved for future use (maintains field alignment)
    #[encdec(with = "arr")]
    reserved: [u8; 3],

    /// The tx_out.public_key field
    #[encdec(with = "pt")]
    pub public_key: CompressedRistrettoPublic,

    /// The tx_out.target_key field
    #[encdec(with = "pt")]
    pub target_key: CompressedRistrettoPublic,

    /// The tx_out.masked_amount.commitment field
    #[encdec(with = "pt")]
    pub commitment: CompressedRistrettoPublic,
}

impl ApduStatic for TxAddTxOut {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxAddTxOut as u8;
}

impl TxAddTxOut {
    /// Create a new add tx out request
    pub fn new(
        ring_index: u8,
        public_key: CompressedRistrettoPublic,
        target_key: CompressedRistrettoPublic,
        commitment: CompressedRistrettoPublic,
    ) -> Self {
        Self {
            ring_index,
            reserved: [0u8; 3],
            public_key,
            target_key,
            commitment,
        }
    }

    /// Build [ReducedTxOut] from [TxAddTxOut] object
    pub fn tx_out(&self) -> ReducedTxOut {
        let commitment: &CompressedRistretto = self.commitment.as_ref();

        ReducedTxOut {
            public_key: self.public_key,
            target_key: self.target_key,
            commitment: CompressedCommitment { point: *commitment },
        }
    }

    /// Compute hash of [TxAddTxOut] object
    pub fn hash(&self) -> [u8; 32] {
        digest_ring_add_txout(self.ring_index, &self.tx_out())
    }
}

/// Execute signing operation for a completed ring (0 length APDU)
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxRingSign;

impl ApduStatic for TxRingSign {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxSign as u8;
}

impl TxRingSign {
    /// Compute hash of [TxRingSign] object
    pub fn hash(&self) -> [u8; 32] {
        digest_ring_sign()
    }
}

/// Fetch a key image for a signed ring, returns [`TxKeyImage`] on success (0-byte APDU)
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxGetKeyImage {}

impl ApduStatic for TxGetKeyImage {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxGetKeyImage as u8;
}

/// Key image response APDU for a signed ring
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                            KEY_IMAGE                          /
/// /                (32-byte Compressed Ristretto Point)           /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                              C_ZERO                           /
/// /                 (32-byte Compressed Curve Point               /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxKeyImage {
    /// Key Image for signed ring
    #[encdec(with = "ki")]
    pub key_image: KeyImage,

    /// Zero'th challenge for signed ring
    #[encdec(with = "scalar")]
    pub c_zero: Scalar,
}

/// Fetch a response scalar for a ring entry in a signed ring, returns [`TxResponse`] on success
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   RING_INDEX  |                   RESERVED                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxGetResponse {
    /// Index of response to be fetched
    pub ring_index: u8,

    /// Reserved for future use
    #[encdec(with = "arr")]
    reserved: [u8; 3],
}

impl TxGetResponse {
    /// Create a new TX response request
    pub fn new(ring_index: u8) -> Self {
        Self {
            ring_index,
            reserved: [0u8; 3],
        }
    }
}

impl ApduStatic for TxGetResponse {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxGetResponse as u8;
}

/// TX Response APDU, contains a response scalar for a given entry in
/// the signed ring.
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   RING_INDEX  |                   RESERVED                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                            RESPONSE                           /
/// /                   (32-byte Ristretto Scalar)                  /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxResponse {
    /// Index of returned response
    pub ring_index: u8,

    /// Reserved bytes (ensures scalar alignment)
    #[encdec(with = "arr")]
    reserved: [u8; 3],

    /// Response scalar
    #[encdec(with = "scalar")]
    pub scalar: Scalar,
}

impl TxResponse {
    /// Create a new tx response response message
    pub fn new(ring_index: u8, scalar: Scalar) -> Self {
        Self {
            ring_index,
            reserved: [0u8; 3],
            scalar,
        }
    }
}

#[cfg(test)]
mod test {
    use mc_crypto_ring_signature::Scalar;
    use rand::{random, rngs::OsRng};

    use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;

    use super::{TxAddTxOut, TxRingInit, TxSetBlinding};
    use crate::test::encode_decode_apdu;

    #[test]
    fn encode_decode_tx_ring_init() {
        let apdu = TxRingInit::new(random(), random(), random(), random(), random());

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn encode_decode_tx_set_blinding() {
        let mut b = [0u8; 256];

        let t = TxSetBlinding {
            blinding: Scalar::random(&mut OsRng {}),
            output_blinding: Scalar::random(&mut OsRng {}),
        };

        encode_decode_apdu(&mut b, &t);
    }

    #[test]
    fn encode_decode_add_txout() {
        let mut b = [0u8; 256];

        let public_key = RistrettoPrivate::from_random(&mut OsRng {});
        let target_key = RistrettoPrivate::from_random(&mut OsRng {});
        let commitment = RistrettoPrivate::from_random(&mut OsRng {});

        let apdu = TxAddTxOut::new(
            random(),
            CompressedRistrettoPublic::from(RistrettoPublic::from(&public_key)),
            CompressedRistrettoPublic::from(RistrettoPublic::from(&target_key)),
            CompressedRistrettoPublic::from(RistrettoPublic::from(&commitment)),
        );

        let n = encode_decode_apdu(&mut b, &apdu);

        assert_eq!(n, 100);
    }
}
