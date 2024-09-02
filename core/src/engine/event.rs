#![allow(unused_imports)]
// Copyright (c) 2022-2023 The MobileCoin Foundation

use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::Digest;
use encdec::{Decode, DecodeOwned};
use sha2::Sha512_256;

use mc_core::{
    account::{PublicSubaddress, ShortAddressHash},
    keys::{SubaddressViewPublic, TxOutPublic},
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature::{CompressedCommitment, CurveScalar, ReducedTxOut, Scalar};
use mc_transaction_types::{Amount, MaskedAmount, UnmaskedAmount};

use ledger_mob_apdu::{
    prelude::*,
    tx::{AddTxInFlags, FogId, TxOnetimeKey, TxRingInitFlags},
};
use ledger_proto::{ApduError, ApduStatic};

/// [`Engine`][super::Engine] input events, typically decoded from request [APDUs][crate::apdu]
#[derive(Clone, Debug)]
pub enum Event {
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
        ident_uri: heapless::String<32>,
        challenge: heapless::Vec<u8, 64>,
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
    TxSetMessage(heapless::Vec<u8, 64>),

    /// Set transaction summary
    /// (replaces TxSetMessage where streaming verification is supported)
    TxSummaryInit {
        message: [u8; 32],
        block_version: u32,
        num_outputs: u32,
        num_inputs: u32,
    },

    /// Add output to TxSummary
    TxSummaryAddOutput {
        masked_amount: Option<MaskedAmount>,
        target_key: CompressedRistrettoPublic,
        public_key: CompressedRistrettoPublic,
        associated_to_input_rules: bool,
    },

    /// Add output unblinding to TxSummary
    TxSummaryAddOutputUnblinding {
        unmasked_amount: UnmaskedAmount,
        address: Option<PublicSubaddress>,
        fog_info: Option<(FogId, [u8; 64])>,
        tx_private_key: Option<TxPrivateKey>,
    },

    /// Add input to TxSummary
    TxSummaryAddInput {
        pseudo_output_commitment: CompressedCommitment,
        input_rules_digest: Option<[u8; 32]>,

        unmasked_amount: UnmaskedAmount,
    },

    /// Build complete TxSummary
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
        onetime_private_key: Option<TxOnetimeKey>,
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
///
/// NOTE: forced-inlining collects the stack into a single frame in [Event::parse]
/// which makes analysis tidier and is a non-critical frame (outside of [Engine::update] path)
#[inline(always)]
fn decode_event<'a, T>(buff: &'a [u8]) -> Result<Event, ApduError>
where
    T: Decode<'a, Error = ApduError>,
    Event: From<T::Output>,
{
    T::decode(buff).map(|(v, _n)| Event::from(v))
}

impl Event {
    /// In-place initialisation
    /// # Safety
    /// This is safe as long as the pointer is valid
    pub unsafe fn init(p: *mut Self) {
        p.write(Self::None);
    }

    /// Parse an incoming APDU to engine event
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn parse(ins: u8, buff: &[u8]) -> Result<Self, ApduError> {
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

            TxRingInit::INS => decode_event::<TxRingInit>(buff),
            TxSetBlinding::INS => decode_event::<TxSetBlinding>(buff),
            TxAddTxOut::INS => decode_event::<TxAddTxOut>(buff),
            TxRingSign::INS => decode_event::<TxRingSign>(buff),
            TxGetKeyImage::INS => decode_event::<TxGetKeyImage>(buff),
            TxGetResponse::INS => decode_event::<TxGetResponse>(buff),

            TxComplete::INS => decode_event::<TxComplete>(buff),

            TxInfoReq::INS => decode_event::<TxInfoReq>(buff),
            _ => unimplemented!(),
        }
    }

    /// Compute a SHA512_256 hash for state-mutating events,
    /// used in the construction of the streaming digest.
    ///
    /// This calls out to [ledger_mob_apdu::digest] methods for
    /// consistency between events and APDUs.
    #[cfg_attr(feature = "noinline", inline(never))]
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
                onetime_private_key,
            } => digest_ring_init(
                *ring_size,
                *real_index,
                subaddress_index,
                value,
                token_id,
                onetime_private_key.as_ref(),
            ),
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

impl From<WalletKeyReq> for Event {
    fn from(a: WalletKeyReq) -> Self {
        Event::GetWalletKeys {
            account_index: a.account_index,
        }
    }
}

impl From<SubaddressKeyReq> for Event {
    fn from(a: SubaddressKeyReq) -> Self {
        Event::GetSubaddressKeys {
            account_index: a.account_index,
            subaddress_index: a.subaddress_index,
        }
    }
}

impl From<KeyImageReq> for Event {
    fn from(a: KeyImageReq) -> Self {
        Event::GetKeyImage {
            account_index: a.account_index,
            subaddress_index: a.subaddress_index,
            txout_public_key: a.txout_public_key,
        }
    }
}

impl From<RandomReq> for Event {
    fn from(_: RandomReq) -> Self {
        Event::GetRandom
    }
}

impl<'a> From<IdentSignReq<'a>> for Event {
    fn from(i: IdentSignReq<'a>) -> Self {
        Event::IdentSign {
            ident_index: i.identity_index,
            ident_uri: heapless::String::try_from(i.identity_uri).unwrap(),
            challenge: heapless::Vec::from_slice(i.challenge).unwrap(),
        }
    }
}

impl From<IdentGetReq> for Event {
    fn from(_i: IdentGetReq) -> Self {
        Event::IdentGet
    }
}

impl From<TxInit> for Event {
    fn from(a: TxInit) -> Self {
        Event::TxInit {
            account_index: a.account_index,
            num_rings: a.num_rings,
        }
    }
}

impl From<TxMemoSign> for Event {
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
impl From<TxSummaryInit> for Event {
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
impl From<TxSummaryAddTxOut> for Event {
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
impl From<TxSummaryAddTxOutUnblinding> for Event {
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
impl From<TxSummaryAddTxIn> for Event {
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
impl From<TxSummaryBuild> for Event {
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

impl From<TxRingInit> for Event {
    fn from(a: TxRingInit) -> Self {
        let onetime_private_key = match a.flags.contains(TxRingInitFlags::HAS_ONETIME_PRIVATE_KEY) {
            true => Some(a.onetime_private_key),
            false => None,
        };

        Event::TxRingInit {
            ring_size: a.ring_size,
            real_index: a.real_index,
            subaddress_index: a.subaddress_index,
            value: a.value,
            token_id: a.token_id,
            onetime_private_key,
        }
    }
}

impl From<TxSetBlinding> for Event {
    fn from(a: TxSetBlinding) -> Self {
        Event::TxSetBlinding {
            blinding: a.blinding,
            output_blinding: a.output_blinding,
        }
    }
}

impl<'a> From<TxSetMessage<'a>> for Event {
    fn from(a: TxSetMessage<'a>) -> Self {
        Event::TxSetMessage(heapless::Vec::from_slice(a.message).unwrap())
    }
}

impl From<TxAddTxOut> for Event {
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

impl From<TxRingSign> for Event {
    fn from(_: TxRingSign) -> Self {
        Event::TxSign
    }
}

impl From<TxGetKeyImage> for Event {
    fn from(_: TxGetKeyImage) -> Self {
        Event::TxGetKeyImage {}
    }
}

impl From<TxGetResponse> for Event {
    fn from(a: TxGetResponse) -> Self {
        Event::TxGetResponse {
            index: a.ring_index,
        }
    }
}

impl From<TxComplete> for Event {
    fn from(_: TxComplete) -> Self {
        Event::TxComplete
    }
}

impl From<TxInfoReq> for Event {
    fn from(_: TxInfoReq) -> Self {
        Event::TxGetInfo
    }
}
