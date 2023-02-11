#![allow(unused)]
// Copyright (c) 2022-2023 The MobileCoin Foundation

use encdec::{Decode, Encode};
use ledger_apdu::ApduStatic;

use mc_core::{
    account::{PublicSubaddress, RingCtAddress, ShortAddressHash},
    keys::{Key, SubaddressSpendPublic, SubaddressViewPublic},
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature::{CompressedCommitment, CurveScalar, Scalar};
#[cfg(feature = "alloc")]
use mc_transaction_types::masked_amount::{MaskedAmount, MaskedAmountV2};
use mc_transaction_types::{amount::Amount, unmasked_amount::UnmaskedAmount};

use crate::{
    digest::{digest_tx_summary_add_output, digest_tx_summary_init},
    helpers::*,
    tx::TxPrivateKey,
    ApduError, Instruction, MOB_APDU_CLA,
};

/// Set TxSummary for a transaction
///
///
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxSummaryInit {
    #[encdec(with = "arr")]
    pub message: [u8; 32],

    pub block_version: u32,

    pub num_inputs: u32,
    pub num_outputs: u32,
}

impl ApduStatic for TxSummaryInit {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxSummaryInit as u8;
}

impl TxSummaryInit {
    /// Create a new [TxSummaryInit] object
    pub fn new(message: [u8; 32], block_version: u32, num_inputs: u32, num_outputs: u32) -> Self {
        Self {
            message,
            block_version,
            num_inputs,
            num_outputs,
        }
    }

    /// Compute the hash of the [TxSummaryInit] object
    pub fn hash(&self) -> [u8; 32] {
        digest_tx_summary_init(
            &self.message,
            &self.block_version,
            &self.num_outputs,
            &self.num_inputs,
        )
    }
}

/// Add TxOutSummary to the summary
///
/// See [mc_transaction_core::tx_summary::TxOutSummary] for equivalence
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxSummaryAddTxOut {
    /// AddTxOut flags
    pub flags: AddTxOutFlags,

    /// TxOut index for idempotency
    pub index: u8,

    pub reserved: [u8; 2],

    /// MaskedAmountV2.masked_value
    pub masked_value: u64,

    /// MaskedAmountV2.masked_token_id
    #[encdec(with = "arr")]
    pub masked_token_id: [u8; 8],

    /// MaskedAmountV2.commitment
    #[encdec(with = "pt")]
    pub commitment: CompressedCommitment,

    /// The one-time public address of this output.
    #[encdec(with = "pt")]
    pub target_key: CompressedRistrettoPublic,

    /// The per output tx public key
    #[encdec(with = "pt")]
    pub public_key: CompressedRistrettoPublic,
}

bitflags::bitflags! {
    /// TxSummaryAddTxOut flags
    pub struct AddTxOutFlags: u8 {
        /// TxOutSummary contains masked amount
        const HAS_MASKED_AMOUNT = 1 << 0;
        /// TxOutSummary associated with input rules
        const ASSOC_INPUT_RULES = 1 << 1;
    }
}

crate::encdec_bitflags!(AddTxOutFlags);

impl ApduStatic for TxSummaryAddTxOut {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxSummaryAddTxOut as u8;
}

impl TxSummaryAddTxOut {
    /// Create a new [TxSummaryAddTxOut] APDU
    ///
    /// (requires `alloc` feature due to [MaskedAmount])
    #[cfg(feature = "alloc")]
    pub fn new(
        index: u8,
        masked_amount: Option<&MaskedAmount>,
        target_key: CompressedRistrettoPublic,
        public_key: CompressedRistrettoPublic,
        associated_to_input_rules: bool,
    ) -> Self {
        let mut flags = AddTxOutFlags::empty();
        flags.set(AddTxOutFlags::HAS_MASKED_AMOUNT, masked_amount.is_some());
        flags.set(AddTxOutFlags::ASSOC_INPUT_RULES, associated_to_input_rules);

        let mut s = Self {
            flags,
            index,
            reserved: [0u8; 2],
            masked_value: 0,
            masked_token_id: [0u8; 8],
            commitment: CompressedCommitment::default(),
            target_key,
            public_key,
        };

        if let Some(m) = masked_amount {
            s.masked_value = *m.get_masked_value();
            s.masked_token_id.copy_from_slice(m.masked_token_id());
            s.commitment = *m.commitment();
        }

        s
    }

    /// Fetch flags
    pub fn flags(&self) -> AddTxOutFlags {
        self.flags
    }

    /// Fetch masked amount if included
    #[cfg(feature = "alloc")]
    pub fn masked_amount(&self) -> Option<MaskedAmount> {
        match self.flags().contains(AddTxOutFlags::HAS_MASKED_AMOUNT) {
            true => Some(MaskedAmount::V2(MaskedAmountV2 {
                commitment: self.commitment,
                masked_value: self.masked_value,
                masked_token_id: self.masked_token_id.to_vec(),
            })),
            false => None,
        }
    }

    /// Compute hash for [TxSummaryAddTxOut]
    pub fn hash(&self) -> [u8; 32] {
        let masked_amount = match self.flags().contains(AddTxOutFlags::HAS_MASKED_AMOUNT) {
            true => Some((
                &self.commitment,
                &self.masked_value,
                &self.masked_token_id[..],
            )),
            false => None,
        };

        digest_tx_summary_add_output(
            masked_amount,
            &self.target_key,
            &self.public_key,
            self.flags().contains(AddTxOutFlags::ASSOC_INPUT_RULES),
        )
    }
}

/// Add TxOutSummaryUnblinding to the summary
///
///
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxSummaryAddTxOutUnblinding {
    /// AddTxOutUnblinding flags
    pub flags: AddTxOutUnblindingFlags,

    /// TxOut index for idempotency
    pub index: u8,

    pub reserved: [u8; 2],

    /// UnmaskedAmount.value
    pub unmasked_value: u64,

    // UnmaskedAmount.token_id
    pub token_id: u64,

    // UnmaskedAmount.blinding
    #[encdec(with = "scalar")]
    pub blinding: Scalar,

    // TxOut receiver spend public key
    #[encdec(with = "pub_key")]
    pub address_spend_public: SubaddressSpendPublic,

    // TxOut receiver view public key
    #[encdec(with = "pub_key")]
    pub address_view_public: SubaddressViewPublic,

    // TxOut receiver short address hash
    #[encdec(with = "arr")]
    pub address_short_hash: [u8; 16],

    // (optional) transaction private key
    #[encdec(with = "pri_key")]
    pub tx_private_key: TxPrivateKey,
}

bitflags::bitflags! {
    /// TxSummaryAddTxOut flags
    pub struct AddTxOutUnblindingFlags: u8 {
        /// TxSummaryAddTxOutUnblinding contains private key
        const HAS_PRIVATE_KEY = 1 << 0;
        /// TxSummaryAddTxOutUnblinding contains address information
        const HAS_ADDRESS = 1 << 1;
    }
}

crate::encdec_bitflags!(AddTxOutUnblindingFlags);

impl ApduStatic for TxSummaryAddTxOutUnblinding {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxSummaryAddTxOutUnblinding as u8;
}

impl TxSummaryAddTxOutUnblinding {
    /// Create a new [TxSummaryAddTxOutUnblinding] APDU
    pub fn new(
        index: u8,
        unmasked_amount: &UnmaskedAmount,
        address: Option<(impl RingCtAddress, ShortAddressHash)>,
        tx_private_key: Option<TxPrivateKey>,
    ) -> Self {
        // Setup flags
        let mut flags = AddTxOutUnblindingFlags::empty();
        flags.set(AddTxOutUnblindingFlags::HAS_ADDRESS, address.is_some());
        flags.set(
            AddTxOutUnblindingFlags::HAS_PRIVATE_KEY,
            tx_private_key.is_some(),
        );

        // Parse address information
        let (address_spend_public, address_view_public, address_short_hash) = match &address {
            Some((keys, hash)) => (
                keys.spend_public_key(),
                keys.view_public_key(),
                hash.clone(),
            ),
            None => (Default::default(), Default::default(), Default::default()),
        };

        // Return object
        Self {
            flags,
            index,
            reserved: [0u8; 2],
            unmasked_value: unmasked_amount.value,
            token_id: unmasked_amount.token_id,
            blinding: unmasked_amount.blinding.into(),
            address_spend_public,
            address_view_public,
            address_short_hash: *address_short_hash.as_ref(),
            tx_private_key: tx_private_key.map(Key::from).unwrap_or_default(),
        }
    }

    pub fn flags(&self) -> AddTxOutUnblindingFlags {
        self.flags
    }

    pub fn unmasked_amount(&self) -> UnmaskedAmount {
        UnmaskedAmount {
            value: self.unmasked_value,
            token_id: self.token_id,
            blinding: self.blinding.into(),
        }
    }

    pub fn tx_private_key(&self) -> Option<&TxPrivateKey> {
        match self
            .flags()
            .contains(AddTxOutUnblindingFlags::HAS_PRIVATE_KEY)
        {
            true => Some(&self.tx_private_key),
            false => None,
        }
    }

    pub fn address(&self) -> Option<(ShortAddressHash, PublicSubaddress)> {
        match self.flags().contains(AddTxOutUnblindingFlags::HAS_ADDRESS) {
            true => Some((
                ShortAddressHash::from(self.address_short_hash),
                PublicSubaddress {
                    view_public: self.address_view_public.clone(),
                    spend_public: self.address_spend_public.clone(),
                },
            )),
            false => None,
        }
    }

    /// Compute hash for [TxSummaryAddTxOutUnblinding]
    pub fn hash(&self) -> [u8; 32] {
        crate::digest::digest_tx_summary_add_output_unblinding(
            &self.unmasked_amount(),
            self.address().as_ref(),
            self.tx_private_key(),
        )
    }
}

/// Add TxInSummary for a transaction
///
///
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxSummaryAddTxIn {
    // Indicates whether input will impact the users balance
    pub flags: AddTxInFlags,

    /// TxIn index for idempotency
    pub index: u8,

    pub reserved: [u8; 2],

    #[encdec(with = "pt")]
    pub pseudo_output_commitment: CompressedCommitment,

    /// UnmaskedAmount.value
    pub unmasked_value: u64,

    // UnmaskedAmount.token_id
    pub token_id: u64,

    // UnmaskedAmount.blinding
    #[encdec(with = "scalar")]
    pub blinding: Scalar,

    /// Digest of input rules per MCIP 52 if has_input_rules is set
    #[encdec(with = "arr")]
    pub input_rules_digest: [u8; 32],
}

bitflags::bitflags! {
    /// TxSummaryAddTxOut flags
    pub struct AddTxInFlags: u8 {
        /// TxInSummary contains input rules digest
        const HAS_INPUT_RULES = 1 << 0;
    }
}

crate::encdec_bitflags!(AddTxInFlags);

impl ApduStatic for TxSummaryAddTxIn {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxSummaryAddTxIn as u8;
}

impl TxSummaryAddTxIn {
    /// Create a new [TxSummaryAddTxIn] APDU
    pub fn new(
        index: u8,
        pseudo_output_commitment: CompressedCommitment,
        unmasked_amount: UnmaskedAmount,
        input_rules_digest: Option<&[u8; 32]>,
    ) -> Self {
        let mut flags = AddTxInFlags::empty();
        flags.set(AddTxInFlags::HAS_INPUT_RULES, input_rules_digest.is_some());

        Self {
            flags,
            index,
            reserved: [0u8; 2],
            pseudo_output_commitment,
            unmasked_value: unmasked_amount.value,
            token_id: unmasked_amount.token_id,
            blinding: unmasked_amount.blinding.into(),
            input_rules_digest: input_rules_digest.copied().unwrap_or_default(),
        }
    }

    /// Fetch the [UnmaskedAmount] from a [TxSummaryAddTxIn] object
    pub fn unmasked_amount(&self) -> UnmaskedAmount {
        UnmaskedAmount {
            value: self.unmasked_value,
            token_id: self.token_id,
            blinding: CurveScalar::from(self.blinding),
        }
    }

    /// Compute hash for [TxSummaryAddTxIn]
    pub fn hash(&self) -> [u8; 32] {
        let input_rules_digest = match self.flags.contains(AddTxInFlags::HAS_INPUT_RULES) {
            true => Some(&self.input_rules_digest),
            false => None,
        };

        crate::digest::digest_tx_summary_add_input(
            &self.pseudo_output_commitment,
            input_rules_digest,
            &self.unmasked_amount(),
        )
    }
}

/// Complete TxSummary building
///
///
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxSummaryBuild {
    pub fee_value: u64,
    pub fee_token_id: u64,
    pub tombstone_block: u64,
}

impl ApduStatic for TxSummaryBuild {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxSummaryBuild as u8;
}

impl TxSummaryBuild {
    /// Create a new [TxSummaryBuild] APDU
    pub fn new(fee: Amount, tombstone_block: u64) -> Self {
        Self {
            fee_value: fee.value,
            fee_token_id: *fee.token_id,
            tombstone_block,
        }
    }

    /// Compute hash for [TxSummaryBuild]
    pub fn hash(&self) -> [u8; 32] {
        crate::digest::digest_tx_summary_build(
            &self.fee_value,
            &self.fee_token_id,
            &self.tombstone_block,
        )
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;
    use rand::random;
    use rand_core::OsRng;

    use super::*;
    use crate::test::encode_decode_apdu;

    #[test]
    fn tx_summary_init() {
        let apdu = TxSummaryInit {
            message: [0xfau8; 32],
            block_version: random(),
            num_inputs: random(),
            num_outputs: random(),
        };

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn tx_summary_add_tx_out() {
        let commitment = RistrettoPoint::random(&mut OsRng {});
        let public_key = RistrettoPublic::from_random(&mut OsRng {});
        let target_key = RistrettoPublic::from_random(&mut OsRng {});

        let apdu = TxSummaryAddTxOut {
            flags: AddTxOutFlags::ASSOC_INPUT_RULES,
            index: random(),
            reserved: [0u8; 2],
            masked_value: random(),
            masked_token_id: random(),
            commitment: commitment.compress().into(),
            target_key: CompressedRistrettoPublic::from(&public_key),
            public_key: CompressedRistrettoPublic::from(&target_key),
        };

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn tx_summary_add_tx_out_unblinding() {
        let view_public = RistrettoPublic::from_random(&mut OsRng {});
        let spend_public = RistrettoPublic::from_random(&mut OsRng {});
        let tx_private_key = RistrettoPrivate::from_random(&mut OsRng {});

        let apdu = TxSummaryAddTxOutUnblinding {
            flags: AddTxOutUnblindingFlags::HAS_ADDRESS,
            index: random(),
            reserved: [0u8; 2],
            unmasked_value: random(),
            token_id: random(),
            blinding: Scalar::random(&mut OsRng {}),
            address_spend_public: view_public.into(),
            address_view_public: spend_public.into(),
            address_short_hash: random(),
            tx_private_key: tx_private_key.into(),
        };

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn tx_summary_add_tx_in() {
        let commitment = RistrettoPoint::random(&mut OsRng {});

        let apdu = TxSummaryAddTxIn {
            flags: AddTxInFlags::HAS_INPUT_RULES,
            index: random(),
            reserved: [0u8; 2],
            unmasked_value: random(),
            token_id: random(),
            pseudo_output_commitment: commitment.compress().into(),
            blinding: Scalar::random(&mut OsRng),
            input_rules_digest: [0xfa; 32],
        };

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn tx_summary_build() {
        let apdu = TxSummaryBuild {
            fee_value: random(),
            fee_token_id: random(),
            tombstone_block: random(),
        };

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }
}
