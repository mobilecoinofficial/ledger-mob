// Copyright (c) 2022-2023 The MobileCoin Foundation

//! The [Engine] provides functionality required by hardware wallets.
//!
//! This handles [Event] inputs and returns [Output] responses to the caller,
//! see [apdu][crate::apdu] for APDU protocol / encoding specifications.

use heapless::Vec;
use rand_core::{CryptoRngCore, OsRng};
use strum::{Display, EnumIter, EnumString, EnumVariantNames};

use mc_core::{
    account::{Account, RingCtAddress},
    keys::{SubaddressViewPublic, TxOutPublic},
    slip10::{wallet_path, Slip10Key},
    subaddress::Subaddress,
};
use mc_crypto_keys::{CompressedRistrettoPublic, KexReusablePrivate, RistrettoPublic};
use mc_crypto_ring_signature::{onetime_keys::recover_onetime_private_key, KeyImage};
pub use mc_transaction_types::{BlockVersion, TokenId};

#[cfg(feature = "memo")]
use mc_crypto_memo_mac::compute_category1_hmac;

#[cfg(feature = "summary")]
use mc_transaction_summary::TxSummaryUnblindingReport;

#[cfg(feature = "summary")]
pub use mc_transaction_summary::TransactionEntity;

mod function;
pub use function::Function;

mod event;
pub use event::Event;

//mod digest;
pub use ledger_mob_apdu::state::Digest as TxDigest;

mod output;
pub use output::Output;

mod error;
pub use error::Error;

mod ring;
pub use ring::{RingState, RESP_SIZE, RING_SIZE};

#[cfg(feature = "ident")]
mod ident;
#[cfg(feature = "ident")]
use ident::{Ident, IdentState};

#[cfg(feature = "summary")]
mod summary;
#[cfg(feature = "summary")]
use summary::SummaryState;

/// Maximum ring message size
const MSG_SIZE: usize = 32;

/// Maximum number of records per summary
#[cfg(feature = "summary")]
const MAX_RECORDS: usize = 16;

/// Engine internal state enumeration
#[derive(Copy, Clone, PartialEq, Debug, EnumString, Display, EnumVariantNames, EnumIter)]
pub enum State {
    /// Idle state, no transaction running
    Init,

    /// Identity request pending approval
    Ident(IdentState),

    /// Transaction init, building memos
    BuildMemos(u8),
    /// Ready to set transaction message
    SetMessage,
    /// Loading TxSummary for verification
    #[cfg(feature = "summary")]
    Summary(SummaryState),
    /// Transaction pending user approval
    Pending,
    /// Ready to start ring signing
    Ready,
    /// Signing ring(s)
    SignRing(RingState),
    /// Transaction denied / aborted
    Deny,
    /// Transaction failed
    Error,
    /// Transaction complete
    Complete,
}

/// [Engine] provides hardware-independent support for MobileCoin wallet operations
///
pub struct Engine<DRV: Driver, RNG: CryptoRngCore = OsRng> {
    state: State,
    unlocked: bool,

    account_index: u32,
    num_rings: usize,

    digest: TxDigest,

    message: Vec<u8, MSG_SIZE>,

    ring_count: usize,

    function: Function,

    drv: DRV,
    rng: RNG,
}

/// [`Driver`] trait provides platform support for [`Engine`] instances
pub trait Driver {
    /// SLIP-0010 derivation for ed25519 keys
    fn slip10_derive_ed25519(&self, path: &[u32]) -> [u8; 32];
}

impl<T: Driver> Driver for &mut T {
    fn slip10_derive_ed25519(&self, path: &[u32]) -> [u8; 32] {
        T::slip10_derive_ed25519(self, path)
    }
}

impl<DRV: Driver> Engine<DRV> {
    /// Create a new transaction engine instance with the provided driver,
    /// using the default [OsRng]
    pub const fn new(drv: DRV) -> Self {
        Self::new_with_rng(drv, OsRng {})
    }
}

impl<DRV: Driver, RNG: CryptoRngCore> Engine<DRV, RNG> {
    /// Create a new transaction engine instance with the provided driver and rng
    pub const fn new_with_rng(drv: DRV, rng: RNG) -> Self {
        Self {
            state: State::Init,
            unlocked: false,
            message: Vec::new(),
            account_index: 0,
            digest: TxDigest::new(),
            num_rings: 0,
            function: Function::new(),
            ring_count: 0,
            rng,
            drv,
        }
    }

    /// Handle incoming transaction events
    // TODO: rejections / timeouts / failure case for transaction aborted half way through?
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn update(&mut self, evt: &Event) -> Result<Output, Error> {
        #[cfg(feature = "log")]
        log::debug!("event: {:02x?}", evt);

        // Update state digest (only applied for mutating events)
        if let Some(h) = evt.hash() {
            self.digest.update(&h);
        }

        // Handle events
        // TODO: handle repeated events in expected state to mitigate retransmission
        // due to loss of ACK/responses via unreliable channels.
        match (self.state, evt) {
            // Empty event, do nothing
            (_, Event::None) => (),

            // Fetch wallet keys
            (_, Event::GetWalletKeys { account_index }) => {
                // Check for unlock state
                if !self.unlocked {
                    return Err(Error::ApprovalPending);
                }

                let account = self.get_account(*account_index);

                return Ok(Output::WalletKeys {
                    account_index: *account_index,
                    spend_public: account.spend_public_key(),
                    view_private: account.view_private_key().clone(),
                });
            }

            // Fetch subaddress keys
            (
                _,
                Event::GetSubaddressKeys {
                    account_index,
                    subaddress_index,
                },
            ) => {
                // Check for unlock state
                if !self.unlocked {
                    return Err(Error::ApprovalPending);
                }

                let account = self.get_account(*account_index);

                let subaddress = account.subaddress(*subaddress_index);

                return Ok(Output::SubaddressKeys {
                    account_index: *account_index,
                    subaddress_index: *subaddress_index,
                    spend_public: subaddress.spend_public_key(),
                    view_private: subaddress.view_private_key().clone(),
                });
            }

            // Compute key image for a given subaddress and tx_public_key
            (
                _,
                Event::GetKeyImage {
                    account_index,
                    subaddress_index,
                    txout_public_key,
                },
            ) => {
                // Check for unlock state
                if !self.unlocked {
                    return Err(Error::ApprovalPending);
                }

                let account = self.get_account(*account_index);
                let subaddress = account.subaddress(*subaddress_index);

                let onetime_private_key = recover_onetime_private_key(
                    txout_public_key.as_ref(),
                    account.view_private_key().as_ref(),
                    subaddress.spend_private_key().as_ref(),
                );

                return Ok(Output::KeyImage {
                    account_index: *account_index,
                    subaddress_index: *subaddress_index,
                    key_image: KeyImage::from(&onetime_private_key),
                });
            }

            // Fetch a random value
            (_, Event::GetRandom) => {
                let mut value = [0xab; 32];
                self.rng.fill_bytes(&mut value);

                return Ok(Output::RandomValue { value });
            }

            // Request identity proof
            #[cfg(feature = "ident")]
            (
                State::Init,
                Event::IdentSign {
                    ident_index,
                    ident_uri,
                    challenge,
                },
            ) => {
                // Setup identity context
                if self
                    .function
                    .ident_init(*ident_index, ident_uri, challenge)
                    .is_err()
                {
                    self.state = State::Error;
                    return Err(Error::Unknown);
                }

                // Move to pending state
                self.state = State::Ident(IdentState::Pending);
            }

            // Derive identity and sign the provided challenge
            #[cfg(feature = "ident")]
            (State::Ident(s), Event::IdentGet) => {
                // Retrieve identity context
                let ident = match self.function.ident_ref() {
                    Some(v) => v,
                    None => {
                        self.state = State::Error;
                        return Err(Error::InvalidState);
                    }
                };

                #[cfg(feature = "log")]
                log::debug!("ident get, state: {:?}", s);

                // Ensure identity request has been approved
                if s != IdentState::Approved {
                    return Err(Error::ApprovalPending);
                }

                // Compute identity object
                let path = ident.path();
                let private_key = self.drv.slip10_derive_ed25519(&path);
                let r = ident.compute(&private_key);

                // Reset engine state
                self.function.clear();
                self.state = State::Init;

                // Return result
                return r;
            }

            // Initialise transaction with private key and value
            (
                _,
                Event::TxInit {
                    account_index,
                    num_rings,
                },
            ) => {
                // Set common transaction information
                self.account_index = *account_index;
                self.num_rings = *num_rings as usize;
                self.digest = TxDigest::from_random(&mut self.rng);

                // TODO: start timeout for transaction completion

                // Set initial tx state and ensure function is
                // clear so prior report cannot be reused.
                self.state = State::BuildMemos(0);
                self.function.clear();
            }

            // Sign memos for the transaction
            #[cfg(feature = "memo")]
            (
                State::BuildMemos(n),
                Event::TxSignMemo {
                    subaddress_index,
                    tx_public_key,
                    receiver_view_public,
                    kind,
                    payload,
                },
            ) => {
                // NOTE: these must be signed prior to the summary construction,
                // so must be allowed without approval / unlocking.
                // this has been deemed non-critical as signed memos are not
                // _useable_ until included in a transaction.

                // Perform memo signing
                let r = self.memo_sign(
                    *subaddress_index,
                    tx_public_key,
                    receiver_view_public,
                    kind,
                    payload,
                )?;

                // Update memo counter
                self.state = State::BuildMemos(n + 1);

                // Return HMAC
                return Ok(r);
            }

            // Set transaction message (direct, bypasses TxSummary verification)
            (State::SetMessage | State::BuildMemos(..), Event::TxSetMessage(m)) => {
                // Check message length
                if m.len() > self.message.capacity() {
                    return Err(Error::InvalidLength);
                }
                // Set message value
                self.message.clear();
                self.message
                    .extend_from_slice(m)
                    .map_err(|_| Error::InvalidLength)?;

                self.state = State::Pending;
            }

            // Start transaction summary
            #[cfg(feature = "summary")]
            (
                State::SetMessage | State::BuildMemos(..),
                Event::TxSummaryInit {
                    message,
                    block_version,
                    num_outputs,
                    num_inputs,
                },
            ) => {
                return self.tx_summary_init(message, *block_version, *num_outputs, *num_inputs);
            }
            // Update transaction summary (pass summary events to summarizer)
            #[cfg(feature = "summary")]
            (
                State::Summary(_),
                Event::TxSummaryAddOutput { .. }
                | Event::TxSummaryAddOutputUnblinding { .. }
                | Event::TxSummaryAddInput { .. }
                | Event::TxSummaryBuild { .. },
            ) => {
                return self.tx_summary_update(evt);
            }

            // Pending user approval (tbd, expect changes when TxSummary lands)
            (State::Pending, _) => {
                // No change, reply with pending state
            }

            // Start ring signing operation
            (
                State::Ready | State::SignRing(..),
                Event::TxRingInit {
                    ring_size,
                    value,
                    token_id,
                    subaddress_index,
                    real_index,
                },
            ) => {
                return self.ring_init(
                    *ring_size,
                    *value,
                    *token_id,
                    *subaddress_index,
                    *real_index,
                );
            }

            // Update ring signature (pass events to ring signer)
            (
                State::SignRing(..),
                Event::TxSetBlinding { .. }
                | Event::TxAddTxout(..)
                | Event::TxSign
                | Event::TxGetKeyImage { .. }
                | Event::TxGetResponse { .. },
            ) => {
                return self.ring_update(evt);
            }

            // Complete transaction
            (_, Event::TxComplete) => {
                // Clear sign context
                self.function.clear();

                // Return to init state
                self.state = State::Complete;
            }

            // Fetch transaction state / information
            (_, Event::TxGetInfo) => (),

            // Handle unexpected events
            _e => {
                #[cfg(feature = "log")]
                log::error!("Unexpected event in state {:?}: {:02x?}", self.state, _e);

                return Err(Error::UnexpectedEvent);
            }
        }

        // Default to returning updated state
        Ok(Output::State {
            state: self.state,
            digest: self.digest.clone(),
        })
    }

    /// Fetch current engine state
    pub fn state(&self) -> State {
        self.state
    }

    /// Fetch an [`Account`] instance for a given wallet index
    pub fn get_account(&self, account_index: u32) -> Account {
        let path = wallet_path(account_index);
        let seed = self.drv.slip10_derive_ed25519(&path);
        Account::from(&Slip10Key::from_raw(seed))
    }

    /// Check whether engine is unlocked (ie. key requests and scanning have been approved)
    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    /// Unlock the engine (allowing key requests and scanning)
    pub fn unlock(&mut self) {
        self.unlocked = true;
    }

    /// Approve a pending transaction (advances state to `State::Ready`)
    pub fn approve(&mut self) {
        if let State::Pending = self.state {
            self.state = State::Ready;
        }
    }

    /// Deny a pending transaction
    pub fn deny(&mut self) {
        self.function.clear();
        self.state = State::Deny;
    }

    /// Reset engine state
    pub fn reset(&mut self) {
        self.function.clear();
        self.state = State::Init;
    }

    /// Fetch progress for non-interactive states (summary, ring signing)
    pub fn progress(&self) -> Option<usize> {
        match self.state {
            #[cfg(feature = "summary")]
            State::Summary(_) => self.function.summarizer_ref().map(|v| v.progress()),
            State::SignRing(_) => self
                .function
                .ring_signer_ref()
                .map(|v| compute_ring_progress(v.progress(), self.ring_count, self.num_rings)),
            _ => None,
        }
    }

    /// Fetch message for transactions in progress
    pub fn message(&self) -> Option<&[u8]> {
        if self.message.len() == 32 {
            Some(&self.message)
        } else {
            None
        }
    }

    /// Return report if available
    #[cfg(feature = "summary")]
    pub fn report(&self) -> Option<&TxSummaryUnblindingReport<MAX_RECORDS>> {
        self.function.summarizer_ref().map(|v| v.report())
    }

    /// Noop report if summary feature is disabled
    #[cfg(not(feature = "summary"))]
    pub fn report(&self) -> Option<()> {
        None
    }

    /// Return ident info if available
    #[cfg(feature = "ident")]
    pub fn ident(&self) -> Option<&Ident> {
        match self.state {
            State::Ident(IdentState::Pending) => (),
            _ => return None,
        }

        self.function.ident_ref()
    }

    /// Approve or deny a pending identity request
    #[cfg(feature = "ident")]
    pub fn ident_approve(&mut self, approve: bool) {
        if let State::Ident(IdentState::Pending) = self.state {
            if approve {
                self.state = State::Ident(IdentState::Approved);
            } else {
                self.function.clear();
                self.state = State::Init;
            }
        }
    }

    // Sign the provided memo, returning an `Output::MemoHmac` on success
    fn memo_sign(
        &mut self,
        subaddress_index: u64,
        tx_out_public_key: &TxOutPublic,
        receiver_view_public: &SubaddressViewPublic,
        kind: &[u8; 2],
        payload: &[u8; 48],
    ) -> Result<Output, Error> {
        // Fetch default subaddress
        let account = self.get_account(self.account_index);
        let sender_subaddr = account.subaddress(subaddress_index);

        // KX using sender default subaddress spend private and receiver subaddress view public
        let sender_spend_private = sender_subaddr.spend_private_key().as_ref();
        let shared_secret = sender_spend_private.key_exchange(receiver_view_public.as_ref());

        // TODO: check memo is supported type (no MEMO_TYPE_BYTES exported yet)

        // Build HMAC
        let tx_out_public_key: &RistrettoPublic = tx_out_public_key.as_ref();
        let hmac_value = compute_category1_hmac(
            shared_secret.as_ref(),
            &CompressedRistrettoPublic::from(tx_out_public_key),
            *kind,
            payload,
        );

        // Return HMAC
        // TODO: useful to ensure hmac|memo correspondence? can't check this on client i think because we don't have the keys
        Ok(Output::MemoHmac {
            state: self.state,
            digest: self.digest.clone(),
            hmac: hmac_value,
        })
    }

    /// Initialise ring signing context
    #[cfg_attr(feature = "noinline", inline(never))]
    fn ring_init(
        &mut self,
        ring_size: u8,
        value: u64,
        token_id: u64,
        subaddress_index: u64,
        real_index: u8,
    ) -> Result<Output, Error> {
        // Preload keys for onetime_private_key recovery on real input
        let account = self.get_account(self.account_index);
        let subaddress = account.subaddress(subaddress_index);

        #[cfg(feature = "log")]
        log::info!("using subaddress {}: {:#?}", subaddress_index, subaddress);

        // Count signed rings
        if self.function.ring_signer_ref().is_some() {
            self.ring_count += 1;
        }

        // Setup ring signer context
        let ctx = self.function.ring_signer_init(
            ring_size as usize,
            real_index as usize,
            account.view_private_key(),
            subaddress.spend_private_key(),
            value,
            &self.message,
            token_id,
        );

        // Handle errors
        match ctx {
            Ok(v) => v,
            Err(e) => {
                #[cfg(feature = "log")]
                log::error!("ring init failed: {:?}", e);

                self.function.clear();
                self.state = State::Error;
                return Err(e);
            }
        };

        self.state = State::SignRing(RingState::Init);

        Ok(Output::State {
            state: self.state,
            digest: self.digest.clone(),
        })
    }

    /// Update ring signing context
    #[cfg_attr(feature = "noinline", inline(never))]
    fn ring_update(&mut self, evt: &Event) -> Result<Output, Error> {
        let ring_signer = match self.function.ring_signer() {
            Some(s) => s,
            _ => {
                self.state = State::Error;
                return Err(Error::UnexpectedEvent);
            }
        };

        let (state, output) = match ring_signer.update(evt, &mut self.rng) {
            Ok(v) => v,
            Err(e) => {
                #[cfg(feature = "log")]
                log::warn!("ring update failed: {:?}", e);

                self.state = State::Error;
                return Err(e);
            }
        };

        // Update engine with new ring signing state
        self.state = State::SignRing(state);

        // Return output or state
        match output {
            Output::None => Ok(Output::State {
                state: self.state,
                digest: self.digest.clone(),
            }),
            _ => Ok(output),
        }
    }

    /// Initialise transaction summary context
    #[cfg(feature = "summary")]
    #[cfg_attr(feature = "noinline", inline(never))]
    fn tx_summary_init(
        &mut self,
        message: &[u8],
        block_version: u32,
        num_outputs: u32,
        num_inputs: u32,
    ) -> Result<Output, Error> {
        // Check streaming message length
        // (note transaction message hash is set later, incoming
        // message is only used for txsummary generation)
        if message.len() > self.message.capacity() {
            return Err(Error::InvalidLength);
        }

        let a = self.get_account(self.account_index);

        // Setup summarizer context
        let _ctx = self.function.summarizer_init(
            message,
            BlockVersion::try_from(block_version).unwrap(),
            num_outputs as usize,
            num_inputs as usize,
            a.view_private_key(),
        );

        self.state = State::Summary(SummaryState::Init);

        Ok(Output::State {
            state: self.state,
            digest: self.digest.clone(),
        })
    }

    /// Update summary context
    #[cfg(feature = "summary")]
    #[cfg_attr(feature = "noinline", inline(never))]
    fn tx_summary_update(&mut self, evt: &Event) -> Result<Output, Error> {
        // Fetch summarizer context
        let summarizer = match self.function.summarizer() {
            Some(s) => s,
            _ => {
                self.state = State::Error;
                return Err(Error::UnexpectedEvent);
            }
        };

        // Handle events
        let r = match evt {
            Event::TxSummaryAddOutput {
                masked_amount,
                target_key,
                public_key,
                associated_to_input_rules,
            } => summarizer.add_output_summary(
                masked_amount.clone(),
                target_key,
                public_key,
                *associated_to_input_rules,
            ),
            Event::TxSummaryAddOutputUnblinding {
                unmasked_amount,
                address,
                tx_private_key,
            } => summarizer.add_output_unblinding(
                unmasked_amount,
                address.clone(),
                tx_private_key.clone(),
            ),
            Event::TxSummaryAddInput {
                pseudo_output_commitment,
                input_rules_digest,
                unmasked_amount,
            } => summarizer.add_input(
                *pseudo_output_commitment,
                *input_rules_digest,
                unmasked_amount,
            ),
            Event::TxSummaryBuild {
                fee,
                tombstone_block,
            } => {
                let mut message = [0u8; 32];
                let r = summarizer.finalize(*fee, *tombstone_block, &mut message);

                // Write message
                self.message.clear();
                let _ = self.message.extend_from_slice(&message);

                r
            }
            // Unhandled event
            _ => {
                self.state = State::Error;
                return Err(Error::UnexpectedEvent);
            }
        };

        // Check results
        match r {
            // On complete, move to tx pending state
            Ok(state) if state == SummaryState::Complete => self.state = State::Pending,
            // Otherwise, update summary state
            Ok(state) => self.state = State::Summary(state),
            // Or handle errors
            Err(e) => {
                #[cfg(feature = "log")]
                log::warn!("summary update failed: {:?}", e);

                self.state = State::Error;
                return Err(e);
            }
        }

        // Return state information
        Ok(Output::State {
            state: self.state,
            digest: self.digest.clone(),
        })
    }
}

fn compute_ring_progress(current: usize, ring: usize, total_rings: usize) -> usize {
    // Check to avoid divide by zero
    if current == 0 && ring == 0 {
        return 0;
    }

    let t = current + (ring * 100);
    let v = t / total_rings;

    debug_assert!(v <= 100);

    v.min(100)
}

#[cfg(test)]
mod test {
    extern crate std;

    use rand_core::OsRng;
    use strum::IntoEnumIterator;

    use mc_core::{account::RingCtAddress, subaddress::Subaddress};
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_crypto_ring_signature::{
        onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
        CompressedCommitment, CurveScalar, MlsagVerify, Scalar,
    };
    use mc_util_from_random::FromRandom;

    use super::*;

    use ledger_mob_tests::mlsag::RingMLSAGParameters;

    lazy_static::lazy_static! {
        pub static ref PRIVATE_KEY: RistrettoPrivate = RistrettoPrivate::from_random(&mut OsRng{});

        /// Mocked out test values, only for state tests
        pub static ref TESTS: [(State, Event<'static>); 4] = [
            (State::Init, Event::TxInit{ account_index: 0, num_rings: 13 }),

            (State::SetMessage, Event::TxSetMessage(&[0xaa, 0xbb, 0xcc])),

            (State::Ready, Event::TxRingInit{ ring_size: RING_SIZE as u8, value: 100, token_id: 10, real_index: 3, subaddress_index: 8 }),

            (State::SignRing(RingState::Init), Event::TxSetBlinding{ blinding: Scalar::random(&mut OsRng{}), output_blinding: Scalar::random(&mut OsRng{})}),

            #[cfg(nyet)]
            (State::BuildRing, Event::TxAddTxout(ReducedTxOut{
                public_key: CompressedRistrettoPublic::from(&PRIVATE_KEY),
                target_key: CompressedRistrettoPublic::from(&PRIVATE_KEY),
                commitment: CompressedCommitment::default(),
            })),
        ];
    }

    /// Driver implementation for test use
    pub struct TestDriver {
        /// BIP39 Mnemonic derived seed
        pub seed: [u8; 32],
    }

    impl TestDriver {
        /// Create a new test driver with a random seed
        pub fn new() -> Self {
            Self {
                seed: rand::random(),
            }
        }

        /// Fetch an account from the seeded test driver
        pub fn account(&self) -> Account {
            let path = wallet_path(0);
            let key = slip10_ed25519::derive_ed25519_private_key(&self.seed, &path);
            Account::from(&Slip10Key::from_raw(key))
        }
    }

    /// Driver impl for test use
    impl Driver for TestDriver {
        fn slip10_derive_ed25519(&self, path: &[u32]) -> [u8; 32] {
            slip10_ed25519::derive_ed25519_private_key(&self.seed, path)
        }
    }

    /// Step through valid events and states
    #[test]
    fn valid_events() {
        let mut e = Engine::new(TestDriver::new());

        for (_state, evt) in &*TESTS {
            // Fire expected event
            let r = e.update(evt);

            // Check response is okay
            assert!(r.is_ok(), "event {evt:?} failed, error response: {r:?}");
        }
    }

    /// Ensure we're handling unexpected events
    #[test]
    fn invalid_events() {
        for (okay_state, evt) in &*TESTS {
            let mut e = Engine::new(TestDriver::new());

            // Fire the same event to every other state
            for state in State::iter() {
                if state == *okay_state {
                    continue;
                }

                match (state, evt) {
                    // Only init once (because this causes a state reset)
                    (State::Init, Event::TxInit { .. }) => (),
                    (_, Event::TxInit { .. }) => continue,
                    // Skip correct state
                    (state, _) if state == *okay_state => continue,
                    _ => (),
                }

                // Fire incorrect event
                let r = e.update(evt);

                // Check engine reports event error
                assert_eq!(r, Err(Error::UnexpectedEvent));
            }
        }
    }

    #[test]
    fn ring_progress() {
        let tests = &[
            (0, 0, 2, 0),
            (50, 0, 2, 25),
            (100, 0, 2, 50),
            (0, 1, 2, 50),
            (50, 1, 2, 75),
            (100, 1, 2, 100),
            (0, 2, 2, 100),
        ];

        for (c, r, t, e) in tests {
            let p = compute_ring_progress(*c, *r, *t);
            assert_eq!(p, *e, "progress error ({}.{}/{})", *r, *c, *t);
        }
    }

    /// Check engine rejects key requests while locked
    #[test]
    fn lock_unlock() {
        let mut e = Engine::new(TestDriver::new());

        // Locked, return pending message
        let r = e.update(&Event::GetWalletKeys { account_index: 0 });
        assert_eq!(r, Err(Error::ApprovalPending));

        let r = e.update(&Event::GetSubaddressKeys {
            account_index: 0,
            subaddress_index: 1,
        });
        assert_eq!(r, Err(Error::ApprovalPending));

        // Unlock engine
        e.unlock();

        // Unlocked, return view account and subaddress keys
        let r = e
            .update(&Event::GetWalletKeys { account_index: 0 })
            .unwrap();
        assert!(matches!(r, Output::WalletKeys { .. }));

        let r = e
            .update(&Event::GetSubaddressKeys {
                account_index: 0,
                subaddress_index: 1,
            })
            .unwrap();
        assert!(matches!(r, Output::SubaddressKeys { .. }));
    }

    use mc_util_test_helper::{RngType, SeedableRng};

    // `sign` should return a signature with correct key image.
    // see: [`mc_crypto_ring_signature::mlsag::mlsag_tests`]
    #[test]
    fn test_sign() {
        let _ = simplelog::TermLogger::init(
            log::LevelFilter::Debug,
            Default::default(),
            simplelog::TerminalMode::Mixed,
            simplelog::ColorChoice::Auto,
        );

        let seed = [0u8; 32];
        let mut rng: RngType = SeedableRng::from_seed(seed);
        let pseudo_output_blinding = Scalar::random(&mut rng);

        let drv = TestDriver::new();
        let account = drv.account();

        let params =
            RingMLSAGParameters::random(&account, RING_SIZE - 1, pseudo_output_blinding, &mut rng);

        let mut engine = Engine::new_with_rng(drv, rng);

        // Initialise new transaction
        let r = engine
            .update(&Event::TxInit {
                account_index: 0,
                num_rings: 1,
            })
            .expect("Init transaction");

        let mut digest = match r {
            Output::State { digest, .. } => digest,
            _ => panic!("Unexpected response: {r:?}"),
        };

        // Set message (shared between rings)
        let evt = Event::TxSetMessage(&params.message);
        let r = engine.update(&evt).expect("Set message");

        assert_eq!(
            r.digest(),
            Some(digest.update(&evt.hash().unwrap())),
            "TX digest mismatch"
        );
        assert_eq!(r.state(), Some(State::Pending));

        // Approve transaction
        engine.approve();

        // Start ring signing
        let evt = Event::TxRingInit {
            ring_size: RING_SIZE as u8,
            value: params.value,
            token_id: params.token_id,
            real_index: params.real_index as u8,
            subaddress_index: params.target_subaddress_index,
        };
        let r = engine.update(&evt).expect("Init ring");

        assert_eq!(
            r.digest(),
            Some(digest.update(&evt.hash().unwrap())),
            "TX digest mismatch"
        );

        // Set blindings
        engine
            .update(&Event::TxSetBlinding {
                blinding: params.blinding,
                output_blinding: pseudo_output_blinding,
            })
            .expect("Set blinding");

        // Load txouts into ring
        for n in 0..RING_SIZE {
            let i = (params.real_index + n) % RING_SIZE;
            let tx_out = &params.ring[i];

            assert_eq!(
                engine.state,
                State::SignRing(RingState::BuildRing(n as u8)),
                "add txout {} invalid state: {:?}",
                i,
                engine.state
            );

            let r = engine
                .update(&Event::TxAddTxout(i as u8, tx_out.clone()))
                .expect("Failed to add txout");

            if n < RING_SIZE - 1 {
                assert_eq!(
                    r,
                    State::SignRing(RingState::BuildRing(n as u8 + 1)),
                    "add txout {} failed (state: {:?})",
                    n,
                    engine.state
                );
            } else {
                assert_eq!(
                    r,
                    State::SignRing(RingState::Execute),
                    "add final txout {} failed (state: {:?})",
                    n,
                    engine.state
                );
            }
        }

        assert_eq!(engine.state, State::SignRing(RingState::Execute));

        // Generate signature
        let state = engine.update(&Event::TxSign).expect("Execute sign");

        // Check key image is valid
        let expected_key_image = KeyImage::from(&params.onetime_private_key);
        let (key_image, c_zero) = match state {
            Output::State {
                state: State::SignRing(RingState::Complete { key_image, c_zero }),
                ..
            } => {
                assert_eq!(key_image, expected_key_image);
                (key_image, c_zero)
            }
            _ => panic!("unexpected state: {state:?}"),
        };

        // Fetch responses
        let responses: Vec<CurveScalar, RESP_SIZE> = (0..RESP_SIZE)
            .map(|i| {
                let resp = engine
                    .update(&Event::TxGetResponse { index: i as u8 })
                    .expect("Fetch response");

                match resp {
                    Output::TxResponse {
                        ring_index: _,
                        scalar,
                    } => scalar.into(),
                    _ => panic!("Unexpected response: {resp:?}"),
                }
            })
            .collect();

        #[cfg(feature = "log")]
        {
            log::debug!("c_zero: {}", CurveScalar::from(c_zero));
            log::debug!("responses: {:#?}", responses);
            log::debug!("key_image: {:#?}", key_image);
        }

        // Recover spend and onetime key for receiver

        let target_subaddr = account.subaddress(params.target_subaddress_index);

        let real_txout = &params.ring[params.real_index];

        let subaddr_spend_key = recover_public_subaddress_spend_key(
            account.view_private_key().as_ref(),
            &RistrettoPublic::try_from(&real_txout.target_key).unwrap(),
            &RistrettoPublic::try_from(&real_txout.public_key).unwrap(),
        );

        let onetime_private_key = recover_onetime_private_key(
            &RistrettoPublic::try_from(&real_txout.public_key).unwrap(),
            account.view_private_key().as_ref(),
            target_subaddr.spend_private_key().as_ref(),
        );

        assert_eq!(
            &subaddr_spend_key,
            &target_subaddr.spend_public_key(),
            "Subaddress spend key recovery mismatch"
        );

        assert_eq!(
            RistrettoPublic::try_from(&real_txout.target_key).unwrap(),
            RistrettoPublic::from(&onetime_private_key),
            "Onetime private key recovery mismatch"
        );

        // Verify ring

        let output_commitment =
            CompressedCommitment::new(params.value, pseudo_output_blinding, &params.generator);

        let verifier = MlsagVerify {
            message: &params.message,
            c_zero: &CurveScalar::from(c_zero),
            responses: responses.as_slice(),
            key_image: &key_image,
            ring: params.ring.as_slice(),
            output_commitment: &output_commitment,
        };

        let mut recomputed_c = [Scalar::default(); RING_SIZE];
        verifier
            .verify(&mut recomputed_c[..])
            .expect("Failed to verify ring");
    }
}
