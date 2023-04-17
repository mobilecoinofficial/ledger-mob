#![allow(unused_imports)]
// Copyright (c) 2022-2023 The MobileCoin Foundation

use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::Digest;
use encdec::Decode;
use sha2::Sha512_256;

use mc_core::{
    account::{PublicSubaddress, ShortAddressHash},
    keys::{SubaddressViewPublic, TxOutPublic},
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature::{CompressedCommitment, CurveScalar, ReducedTxOut, Scalar};

#[cfg(feature = "summary")]
use mc_transaction_types::{Amount, MaskedAmount, UnmaskedAmount};

use ledger_apdu::{ApduError, ApduStatic};
use ledger_mob_apdu::{
    prelude::*,
    tx::{AddTxInFlags, FogId},
};

/// [`Engine`][super::Engine] input events, typically decoded from request [APDUs][crate::apdu]
#[derive(Clone, Debug)]
pub enum Event<'a> {
    None,

    /// Fetch wallet keys
    GetWalletKeys {
        account_index: u32,
    },

    /// Fetch subaddress keys
    GetSubaddressKeys {
        account_index: u32,
        subaddress_index: u64,
    },

    /// Fetch key image
    GetKeyImage {
        account_index: u32,
        subaddress_index: u64,
        txout_public_key: TxOutPublic,
    },

    /// Fetch random value via RNG
    GetRandom,

    /// Request BIP-0017 derived ed25519 identity
    IdentSign {
        ident_index: u32,
        ident_uri: &'a str,
        challenge: &'a [u8],
    },

    /// Fetch signed identity
    IdentGet,

    /// Initialise transaction
    TxInit {
        account_index: u32,
        num_rings: u8,
    },

    /// Sign transaction memos
    TxSignMemo {
        subaddress_index: u64,
        tx_public_key: TxOutPublic,
        receiver_view_public: SubaddressViewPublic,
        kind: [u8; 2],
        payload: [u8; 48],
    },

    /// Set transaction message
    TxSetMessage(&'a [u8]),

    /// Set transaction summary
    /// (replaces TxSetMessage where streaming verification is supported)
    #[cfg(feature = "summary")]
    TxSummaryInit {
        message: [u8; 32],
        block_version: u32,
        num_outputs: u32,
        num_inputs: u32,
    },

    /// Add output to TxSummary
    #[cfg(feature = "summary")]
    TxSummaryAddOutput {
        masked_amount: Option<MaskedAmount>,
        target_key: CompressedRistrettoPublic,
        public_key: CompressedRistrettoPublic,
        associated_to_input_rules: bool,
    },

    /// Add output unblinding to TxSummary
    #[cfg(feature = "summary")]
    TxSummaryAddOutputUnblinding {
        unmasked_amount: UnmaskedAmount,
        address: Option<PublicSubaddress>,
        fog_info: Option<(FogId, [u8; 64])>,
        tx_private_key: Option<TxPrivateKey>,
    },

    /// Add input to TxSummary
    #[cfg(feature = "summary")]
    TxSummaryAddInput {
        pseudo_output_commitment: CompressedCommitment,
        input_rules_digest: Option<[u8; 32]>,

        unmasked_amount: UnmaskedAmount,
    },

    /// Build complete TxSummary
    #[cfg(feature = "summary")]
    TxSummaryBuild {
        fee: Amount,
        tombstone_block: u64,
    },

    /// Initialise ring signing
    TxRingInit {
        ring_size: u8,
        real_index: u8,
        subaddress_index: u64,
        value: u64,
        token_id: u64,
    },

    // Setup blinding
    TxSetBlinding {
        blinding: Scalar,
        output_blinding: Scalar,
    },

    /// Add TxOut to ring
    TxAddTxout(u8, ReducedTxOut),

    /// Sign ring
    TxSign,

    /// Fetch key image
    TxGetKeyImage,

    /// Fetch responses
    TxGetResponse {
        /// Index into ring
        index: u8,
    },

    /// Complete transaction
    TxComplete,

    /// Fetch TX info / state
    TxGetInfo,
}

/// Helper for decoding APDUs to events
fn decode_event<'a, T>(buff: &'a [u8]) -> Result<Event, ApduError>
where
    T: Decode<'a, Error = ApduError>,
    Event<'a>: From<T::Output>,
{
    T::decode(buff).map(|(v, _n)| Event::from(v))
}

impl<'a> Event<'a> {
    /// Parse an incoming APDU to engine event
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn parse(ins: u8, buff: &'a [u8]) -> Result<Self, ApduError> {
        match ins {
            WalletKeyReq::INS => decode_event::<WalletKeyReq>(buff),
            SubaddressKeyReq::INS => decode_event::<SubaddressKeyReq>(buff),
            KeyImageReq::INS => decode_event::<KeyImageReq>(buff),
            RandomReq::INS => decode_event::<RandomReq>(buff),

            IdentSignReq::INS => decode_event::<IdentSignReq>(buff),
            IdentGetReq::INS => decode_event::<IdentGetReq>(buff),

            TxInit::INS => decode_event::<TxInit>(buff),
            TxMemoSign::INS => decode_event::<TxMemoSign>(buff),

            #[cfg(feature = "summary")]
            TxSummaryInit::INS => decode_event::<TxSummaryInit>(buff),
            #[cfg(feature = "summary")]
            TxSummaryAddTxIn::INS => decode_event::<TxSummaryAddTxIn>(buff),
            #[cfg(feature = "summary")]
            TxSummaryAddTxOut::INS => decode_event::<TxSummaryAddTxOut>(buff),
            #[cfg(feature = "summary")]
            TxSummaryAddTxOutUnblinding::INS => decode_event::<TxSummaryAddTxOutUnblinding>(buff),
            #[cfg(feature = "summary")]
            TxSummaryBuild::INS => decode_event::<TxSummaryBuild>(buff),

            TxSetMessage::INS => decode_event::<TxSetMessage>(buff),

            TxRingInit::INS => TxRingInit::decode(buff).map(|(apdu, _n)| Event::from(apdu)),
            TxSetBlinding::INS => decode_event::<TxSetBlinding>(buff),
            TxAddTxOut::INS => TxAddTxOut::decode(buff).map(|(apdu, _n)| Event::from(apdu)),
            TxRingSign::INS => TxRingSign::decode(buff).map(|(apdu, _n)| Event::from(apdu)),
            TxGetKeyImage::INS => decode_event::<TxGetKeyImage>(buff),
            TxGetResponse::INS => decode_event::<TxGetResponse>(buff),

            TxComplete::INS => TxComplete::decode(buff).map(|(apdu, _n)| Event::from(apdu)),

            TxInfoReq::INS => TxInfoReq::decode(buff).map(|(apdu, _n)| Event::from(apdu)),
            _ => unimplemented!(),
        }
    }

    /// Compute a SHA512_256 hash for state-mutating events,
    /// used in the construction of the streaming digest.
    ///
    /// This calls out to [ledger_mob_apdu::digest] methods for
    /// consistency between events and APDUs.
    pub fn hash(&self) -> Option<[u8; 32]> {
        use ledger_mob_apdu::digest::*;

        // Update based on event.updates
        let h = match self {
            Event::TxInit {
                account_index,
                num_rings,
            } => digest_tx_init(account_index, *num_rings),
            Event::TxSignMemo {
                subaddress_index,
                tx_public_key,
                receiver_view_public,
                kind,
                payload,
            } => digest_tx_sign_memo(
                subaddress_index,
                tx_public_key,
                receiver_view_public,
                kind,
                payload,
            ),

            // Set message (blind transactions)
            Event::TxSetMessage(m) => digest_tx_set_message(m),

            // TODO: Summary updates
            Event::TxSummaryInit {
                message,
                block_version,
                num_outputs,
                num_inputs,
            } => digest_tx_summary_init(message, block_version, num_outputs, num_inputs),
            Event::TxSummaryAddOutput {
                masked_amount,
                target_key,
                public_key,
                associated_to_input_rules,
            } => digest_tx_summary_add_output(
                masked_amount
                    .as_ref()
                    .map(|a| (a.commitment(), a.get_masked_value(), a.masked_token_id())),
                target_key,
                public_key,
                *associated_to_input_rules,
            ),
            Event::TxSummaryAddOutputUnblinding {
                unmasked_amount,
                address,
                fog_info,
                tx_private_key,
            } => digest_tx_summary_add_output_unblinding(
                unmasked_amount,
                address.as_ref(),
                tx_private_key.as_ref(),
                fog_info.as_ref().map(|(_id, sig)| &sig[..]),
            ),
            Event::TxSummaryAddInput {
                pseudo_output_commitment,
                input_rules_digest,
                unmasked_amount,
            } => digest_tx_summary_add_input(
                pseudo_output_commitment,
                input_rules_digest.as_ref(),
                unmasked_amount,
            ),
            Event::TxSummaryBuild {
                fee,
                tombstone_block,
            } => digest_tx_summary_build(&fee.value, &fee.token_id, tombstone_block),

            // Ring updates
            Event::TxRingInit {
                ring_size,
                real_index,
                subaddress_index,
                value,
                token_id,
            } => digest_ring_init(*ring_size, *real_index, subaddress_index, value, token_id),
            Event::TxSetBlinding {
                blinding,
                output_blinding,
            } => digest_ring_set_blinding(blinding, output_blinding),

            Event::TxAddTxout(n, tx_out) => digest_ring_add_txout(*n, tx_out),
            Event::TxSign => digest_ring_sign(),
            _ => return None,
        };

        Some(h)
    }
}

impl<'a> From<WalletKeyReq> for Event<'a> {
    fn from(a: WalletKeyReq) -> Self {
        Event::GetWalletKeys {
            account_index: a.account_index,
        }
    }
}

impl<'a> From<SubaddressKeyReq> for Event<'a> {
    fn from(a: SubaddressKeyReq) -> Self {
        Event::GetSubaddressKeys {
            account_index: a.account_index,
            subaddress_index: a.subaddress_index,
        }
    }
}

impl<'a> From<KeyImageReq> for Event<'a> {
    fn from(a: KeyImageReq) -> Self {
        Event::GetKeyImage {
            account_index: a.account_index,
            subaddress_index: a.subaddress_index,
            txout_public_key: a.txout_public_key,
        }
    }
}

impl<'a> From<RandomReq> for Event<'a> {
    fn from(_: RandomReq) -> Self {
        Event::GetRandom
    }
}

impl<'a> From<IdentSignReq<'a>> for Event<'a> {
    fn from(i: IdentSignReq<'a>) -> Self {
        Event::IdentSign {
            ident_index: i.identity_index,
            ident_uri: i.identity_uri,
            challenge: i.challenge,
        }
    }
}

impl<'a> From<IdentGetReq> for Event<'a> {
    fn from(_i: IdentGetReq) -> Self {
        Event::IdentGet
    }
}

impl<'a> From<TxInit> for Event<'a> {
    fn from(a: TxInit) -> Self {
        Event::TxInit {
            account_index: a.account_index,
            num_rings: a.num_rings,
        }
    }
}

impl<'a> From<TxMemoSign> for Event<'a> {
    fn from(a: TxMemoSign) -> Self {
        Event::TxSignMemo {
            subaddress_index: a.subaddress_index,
            tx_public_key: a.tx_public_key,
            receiver_view_public: a.target_view_public,
            kind: a.kind,
            payload: a.payload,
        }
    }
}

#[cfg(feature = "summary")]
impl<'a> From<TxSummaryInit> for Event<'a> {
    fn from(a: TxSummaryInit) -> Self {
        Event::TxSummaryInit {
            message: a.message,
            block_version: a.block_version,
            num_outputs: a.num_outputs,
            num_inputs: a.num_inputs,
        }
    }
}

#[cfg(feature = "summary")]
impl<'a> From<TxSummaryAddTxOut> for Event<'a> {
    fn from(a: TxSummaryAddTxOut) -> Self {
        Event::TxSummaryAddOutput {
            masked_amount: a.masked_amount(),
            target_key: a.target_key,
            public_key: a.public_key,
            associated_to_input_rules: a.flags().contains(AddTxOutFlags::ASSOC_INPUT_RULES),
        }
    }
}

#[cfg(feature = "summary")]
impl<'a> From<TxSummaryAddTxOutUnblinding> for Event<'a> {
    fn from(a: TxSummaryAddTxOutUnblinding) -> Self {
        Event::TxSummaryAddOutputUnblinding {
            unmasked_amount: UnmaskedAmount {
                value: a.unmasked_value,
                token_id: a.token_id,
                blinding: CurveScalar::from(a.blinding),
            },
            address: a.address(),
            fog_info: a.fog_info(),
            tx_private_key: a.tx_private_key().cloned(),
        }
    }
}

#[cfg(feature = "summary")]
impl<'a> From<TxSummaryAddTxIn> for Event<'a> {
    fn from(a: TxSummaryAddTxIn) -> Self {
        let input_rules_digest = match a.flags.contains(AddTxInFlags::HAS_INPUT_RULES) {
            true => Some(a.input_rules_digest),
            false => None,
        };

        Event::TxSummaryAddInput {
            pseudo_output_commitment: a.pseudo_output_commitment,
            input_rules_digest,
            unmasked_amount: a.unmasked_amount(),
        }
    }
}

#[cfg(feature = "summary")]
impl<'a> From<TxSummaryBuild> for Event<'a> {
    fn from(a: TxSummaryBuild) -> Self {
        Event::TxSummaryBuild {
            fee: Amount {
                value: a.fee_value,
                token_id: a.fee_token_id.into(),
            },
            tombstone_block: a.tombstone_block,
        }
    }
}

impl<'a> From<TxRingInit> for Event<'a> {
    fn from(a: TxRingInit) -> Self {
        Event::TxRingInit {
            ring_size: a.ring_size,
            real_index: a.real_index,
            subaddress_index: a.subaddress_index,
            value: a.value,
            token_id: a.token_id,
        }
    }
}

impl<'a> From<TxSetBlinding> for Event<'a> {
    fn from(a: TxSetBlinding) -> Self {
        Event::TxSetBlinding {
            blinding: a.blinding,
            output_blinding: a.output_blinding,
        }
    }
}

impl<'a> From<TxSetMessage<'a>> for Event<'a> {
    fn from(a: TxSetMessage<'a>) -> Self {
        Event::TxSetMessage(a.message)
    }
}

impl<'a> From<TxAddTxOut> for Event<'a> {
    fn from(a: TxAddTxOut) -> Self {
        let commitment: &CompressedRistretto = a.commitment.as_ref();

        Event::TxAddTxout(
            a.ring_index,
            ReducedTxOut {
                public_key: a.public_key,
                target_key: a.target_key,
                commitment: CompressedCommitment { point: *commitment },
            },
        )
    }
}

impl<'a> From<TxRingSign> for Event<'a> {
    fn from(_: TxRingSign) -> Self {
        Event::TxSign
    }
}

impl<'a> From<TxGetKeyImage> for Event<'a> {
    fn from(_: TxGetKeyImage) -> Self {
        Event::TxGetKeyImage {}
    }
}

impl<'a> From<TxGetResponse> for Event<'a> {
    fn from(a: TxGetResponse) -> Self {
        Event::TxGetResponse {
            index: a.ring_index,
        }
    }
}

impl<'a> From<TxComplete> for Event<'a> {
    fn from(_: TxComplete) -> Self {
        Event::TxComplete
    }
}

impl<'a> From<TxInfoReq> for Event<'a> {
    fn from(_: TxInfoReq) -> Self {
        Event::TxGetInfo
    }
}
