// Copyright (c) 2022-2023 The MobileCoin Foundation

use encdec::Encode;

use ledger_proto::ApduError;
use mc_core::keys::{
    RootSpendPublic, RootViewPrivate, SubaddressSpendPublic, SubaddressViewPrivate,
};
use mc_crypto_ring_signature::{KeyImage, Scalar};

pub use ledger_mob_apdu::state::Digest as TxDigest;

use crate::{apdu, engine::ring::RingState};

#[cfg(feature = "summary")]
use super::summary::SummaryState;

#[cfg(feature = "ident")]
use super::ident::IdentState;

/// [`Engine`][super::Engine] outputs (in response to events), typically encoded to response [APDUs][crate::apdu]
#[derive(Clone, PartialEq, Debug)]
pub enum Output {
    None,

    /// Engine state
    State {
        state: super::State,
        digest: TxDigest,
    },

    /// Wallet keys
    WalletKeys {
        account_index: u32,
        spend_public: RootSpendPublic,
        view_private: RootViewPrivate,
    },

    /// Subaddress keys
    SubaddressKeys {
        account_index: u32,
        subaddress_index: u64,
        spend_public: SubaddressSpendPublic,
        view_private: SubaddressViewPrivate,
    },

    /// Computed key image
    KeyImage {
        account_index: u32,
        subaddress_index: u64,
        key_image: KeyImage,
    },

    /// Random value
    RandomValue {
        value: [u8; 32],
    },

    /// BIP-0017 derived identity and challenge
    Identity {
        public_key: [u8; 32],
        signature: [u8; 64],
    },

    /// HMAC for signed memo
    MemoHmac {
        state: super::State,
        digest: TxDigest,
        hmac: [u8; 16],
    },

    /// Key image (and c_zero) from signed ring
    TxKeyImage {
        key_image: KeyImage,
        c_zero: Scalar,
    },

    /// Response entry from a signed ring
    TxResponse {
        ring_index: u8,
        scalar: Scalar,
    },

    /// Indicate the device is waiting for user input
    Pending,
}

impl Output {
    /// Initialise an [Output] pointer without allocation
    /// # Safety
    /// This is safe as long as the pointer is valid
    pub unsafe fn init(ptr: *mut Self) {
        ptr.write(Output::None);
    }

    /// Encode an [`Output`] object to a response [APDU]
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn encode(&self, buff: &mut [u8]) -> Result<usize, ApduError> {
        match self.clone() {
            Output::None => Ok(0),
            Output::State { state, digest } => apdu::tx::TxInfo {
                state: state.state(),
                value: state.value(),
                digest,
            }
            .encode(buff),
            Output::WalletKeys {
                account_index,
                spend_public,
                view_private,
            } => apdu::wallet_keys::WalletKeyResp {
                account_index,
                spend_public,
                view_private,
            }
            .encode(buff),
            Output::SubaddressKeys {
                account_index,
                subaddress_index,
                spend_public,
                view_private,
            } => apdu::subaddress_keys::SubaddressKeyResp {
                account_index,
                subaddress_index,
                spend_public,
                view_private,
            }
            .encode(buff),
            Output::KeyImage {
                account_index,
                subaddress_index,
                key_image,
            } => apdu::key_image::KeyImageResp {
                account_index,
                subaddress_index,
                key_image,
            }
            .encode(buff),
            Output::RandomValue { value } => apdu::random::RandomResp { value }.encode(buff),
            Output::Identity {
                public_key,
                signature,
            } => apdu::ident::IdentResp {
                public_key,
                signature,
            }
            .encode(buff),
            Output::MemoHmac {
                state,
                digest,
                hmac,
            } => apdu::tx::TxMemoSig {
                state: state.state(),
                digest,
                value: state.value(),
                hmac,
            }
            .encode(buff),
            Output::TxKeyImage { key_image, c_zero } => {
                apdu::tx::TxKeyImage { key_image, c_zero }.encode(buff)
            }
            Output::TxResponse { ring_index, scalar } => {
                apdu::tx::TxResponse::new(ring_index, scalar).encode(buff)
            }
            Output::Pending => Ok(0),
        }
    }

    /// Fetch state for outputs containing this
    pub fn state(&self) -> Option<super::State> {
        match &self {
            Output::State { state, .. } => Some(*state),
            _ => None,
        }
    }

    /// Fetch digestfor outputs containing this
    pub fn digest(&self) -> Option<&TxDigest> {
        match &self {
            Output::State { digest, .. } => Some(digest),
            _ => None,
        }
    }
}

impl PartialEq<super::State> for Output {
    fn eq(&self, other: &super::State) -> bool {
        match self {
            Output::State { state, .. } => state == other,
            _ => false,
        }
    }
}

#[cfg(nope)]
impl From<(crate::engine::State, TxDigest)> for apdu::tx::TxInfo {
    fn from(s: (crate::engine::State, TxDigest)) -> Self {
        apdu::tx::TxInfo {
            state: s.0.state(),
            value: s.0.value(),
            digest: s.1,
        }
    }
}

impl crate::engine::State {
    /// Map [engine](crate::engine) states to [apdu][apdu::state::TxState] states for transmission
    pub fn state(&self) -> apdu::state::TxState {
        use crate::{apdu::state::TxState, engine::State};

        match self {
            State::Init => TxState::Init,
            #[cfg(feature = "ident")]
            State::Ident(s) => match s {
                IdentState::Pending => TxState::IdentPending,
                IdentState::Approved => TxState::IdentApproved,
                IdentState::Denied => TxState::IdentDenied,
            },
            State::Ready => TxState::Ready,
            State::BuildMemos(_n) => TxState::SignMemos,
            State::SetMessage => TxState::SetMessage,
            #[cfg(feature = "summary")]
            State::Summary(s) => match s {
                SummaryState::Init => TxState::SummaryInit,
                SummaryState::AddTxIn(_) => TxState::SummaryAddTxIn,
                SummaryState::AddTxOut(_) => TxState::SummaryAddTxOut,
                SummaryState::Ready => TxState::SummaryReady,
                SummaryState::Complete => TxState::SummaryComplete,
            },
            State::Pending => TxState::Pending,
            State::SignRing(RingState::Init) => TxState::RingInit,
            State::SignRing(RingState::BuildRing(_n)) => TxState::RingBuild,
            State::SignRing(RingState::Execute) => TxState::RingSign,
            State::SignRing(RingState::Complete { .. }) => TxState::RingComplete,
            State::Deny => TxState::TxDenied,
            State::Error | State::SignRing(RingState::Error) => TxState::Error,
            State::Complete => TxState::TxComplete,
        }
    }

    pub fn value(&self) -> u16 {
        use crate::engine::State;

        match self {
            State::BuildMemos(n) => *n as u16,
            State::SignRing(RingState::BuildRing(n)) => *n as u16,
            #[cfg(feature = "summary")]
            State::Summary(SummaryState::AddTxOut(n)) => *n as u16,
            #[cfg(feature = "summary")]
            State::Summary(SummaryState::AddTxIn(n)) => *n as u16,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::apdu::state::TxState;
    use crate::engine::{RingState, State};

    // Ensure state mappings match
    #[test]
    fn state_encode_decode() {
        let tests = &[
            (State::Init, TxState::Init),
            (State::Ready, TxState::Ready),
            (State::BuildMemos(0), TxState::SignMemos),
            (State::SetMessage, TxState::SetMessage),
            (State::Pending, TxState::Pending),
            (State::SignRing(RingState::Init), TxState::RingInit),
            (State::SignRing(RingState::BuildRing(0)), TxState::RingBuild),
            (State::SignRing(RingState::Execute), TxState::RingSign),
            (
                State::SignRing(RingState::Complete {
                    key_image: Default::default(),
                    c_zero: Default::default(),
                }),
                TxState::RingComplete,
            ),
            (State::Error, TxState::Error),
            (State::SignRing(RingState::Error), TxState::Error),
        ];

        for (a, b) in tests {
            assert_eq!(a.state(), *b);
        }
    }
}
