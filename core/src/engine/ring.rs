// Copyright (c) 2022-2023 The MobileCoin Foundation

use core::ptr::addr_of_mut;

use heapless::Vec;
use ledger_mob_apdu::tx::TxOnetimeKey;
use strum::{Display, EnumIter, EnumString, EnumVariantNames};
use zeroize::Zeroize;

use super::{Error, Event, Output};
use mc_core::keys::{RootViewPrivate, SubaddressSpendPrivate};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{
    generators, onetime_keys::recover_onetime_private_key, CurveScalar, KeyImage, MlsagSignCtx,
    MlsagSignParams, PedersenGens, ReducedTxOut, Scalar,
};
use rand_core::{CryptoRng, RngCore};

/// Maximum ring size
pub const RING_SIZE: usize = 11;

/// Ring response size (2 * RING_SIZE)
pub const RESP_SIZE: usize = RING_SIZE * 2;

/// Maximum message size
const MESSAGE_MAX: usize = 66;

/// Heapless based MlsagSignCtx
pub type SignCtx = MlsagSignCtx<Vec<CurveScalar, RESP_SIZE>>;

/// Ring signing states
#[derive(Copy, Clone, PartialEq, Debug, EnumString, Display, EnumVariantNames, EnumIter)]
pub enum RingState {
    Init,
    BuildRing(u8),
    Execute,
    Complete { key_image: KeyImage, c_zero: Scalar },
    Error,
}

impl Default for RingState {
    fn default() -> Self {
        Self::Init
    }
}

/// Ring signer state machine
pub struct RingSigner {
    /// State, mutated by events etc.
    state: RingState,

    /// Size of ring to be signed
    ring_size: usize,

    /// Transaction onetime private key
    onetime_private_key: Option<RistrettoPrivate>,

    ///
    root_view_private: RootViewPrivate,

    ///
    subaddress_spend_private: SubaddressSpendPrivate,

    /// Transaction value
    value: u64,

    /// Real entry index
    real_index: usize,

    /// Message for signing in ring
    message: Vec<u8, MESSAGE_MAX>,

    /// Generator for the ring (derived from token_id)
    generator: PedersenGens,

    /// Blinding values for ring
    blindings: Option<Blindings>,

    /// MLSAG context
    ring_ctx: Option<SignCtx>,

    /// Counter for fetched responses (used for progress tracking)
    fetch_count: usize,
}

/// Ring blindings container
struct Blindings {
    blinding: Scalar,
    output_blinding: Scalar,
}

impl RingSigner {
    /// Create new RingSigner instance with provided params
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ring_size: usize,
        real_index: usize,
        root_view_private: &RootViewPrivate,
        subaddress_spend_private: &SubaddressSpendPrivate,
        value: u64,
        message: &[u8],
        token_id: u64,
        onetime_private_key: Option<TxOnetimeKey>,
    ) -> Result<Self, Error> {
        // Check ring size and real index are valid
        if ring_size > RING_SIZE || real_index > RING_SIZE || real_index > ring_size {
            return Err(Error::RingInitFailed);
        }
        // Check message length is valid
        if message.len() > MESSAGE_MAX {
            return Err(Error::RingInitFailed);
        }

        Ok(Self {
            state: RingState::Init,
            ring_size,
            real_index,
            root_view_private: root_view_private.clone(),
            subaddress_spend_private: subaddress_spend_private.clone(),
            onetime_private_key: onetime_private_key.map(|k| k.inner()),
            value,
            message: Vec::from_slice(message).map_err(|_| Error::InvalidLength)?,
            generator: generators(token_id),
            blindings: None,
            ring_ctx: None,
            fetch_count: 0,
        })
    }

    /// Create new RingSigner instance with provided params (out-pointer version)
    ///
    /// out-pointer based init to avoid stack allocation
    /// used by `Function::ring_sign_init`
    /// see: https://doc.rust-lang.org/core/mem/union.MaybeUninit.html#out-pointers
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(feature = "noinline", inline(never))]
    pub(crate) unsafe fn init(
        p: *mut Self,
        ring_size: usize,
        real_index: usize,
        root_view_private: &RootViewPrivate,
        subaddress_spend_private: &SubaddressSpendPrivate,
        value: u64,
        message: &[u8],
        token_id: u64,
        onetime_private_key: Option<TxOnetimeKey>,
    ) -> Result<(), Error> {
        // Check ring size and real inputs are valid
        if ring_size > RING_SIZE || real_index > RING_SIZE || real_index > ring_size {
            return Err(Error::RingInitFailed);
        }
        // Check message length is valid
        if message.len() > MESSAGE_MAX {
            return Err(Error::RingInitFailed);
        }

        // Per-field init to avoid allocating a whole object just for setup
        // (another stack use minimization hijink)
        addr_of_mut!((*p).state).write(RingState::Init);
        addr_of_mut!((*p).ring_size).write(ring_size);
        addr_of_mut!((*p).real_index).write(real_index);
        addr_of_mut!((*p).root_view_private).write(root_view_private.clone());
        addr_of_mut!((*p).subaddress_spend_private).write(subaddress_spend_private.clone());

        let onetime_private_key = onetime_private_key.map(|k| k.inner());
        addr_of_mut!((*p).onetime_private_key).write(onetime_private_key);

        addr_of_mut!((*p).value).write(value);
        addr_of_mut!((*p).message)
            .write(Vec::from_slice(message).map_err(|_| Error::InvalidLength)?);
        addr_of_mut!((*p).generator).write(generators(token_id));
        addr_of_mut!((*p).blindings).write(None);
        addr_of_mut!((*p).ring_ctx).write(None);
        addr_of_mut!((*p).fetch_count).write(0);

        Ok(())
    }

    /// Update RingSigner with the provided event
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn update(
        &mut self,
        evt: &Event,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(RingState, Output), Error> {
        #[cfg(feature = "log")]
        log::debug!("ring update (state: {:?}): {:?}", self.state, evt);

        match (self.state, evt) {
            // Add blinding scalars for ring
            (
                RingState::Init,
                Event::TxSetBlinding {
                    blinding,
                    output_blinding,
                },
            ) => {
                self.blindings = Some(Blindings {
                    blinding: *blinding,
                    output_blinding: *output_blinding,
                });

                self.state = RingState::BuildRing(0);
            }

            // Add txouts to ring
            (RingState::BuildRing(n), Event::TxAddTxout(index, txout)) => {
                // On the first entry (ie. the real one),
                if n == 0 {
                    // Initialise the ring signing context and recover the onetime_private_key
                    if let Err(e) = self.ring_init(txout, rng) {
                        #[cfg(feature = "log")]
                        log::error!("ring init failed: {:?}", e);

                        self.state = RingState::Error;
                        return Err(e);
                    }
                }

                // Add tx_out to ring
                if let Err(e) = self.ring_update(*index as usize, txout) {
                    #[cfg(feature = "log")]
                    log::error!("ring update failed: {:?}", e);

                    self.state = RingState::Error;
                    return Err(e);
                };

                // Move on when we have enough ring entries
                if (n + 1) as usize == self.ring_size {
                    self.state = RingState::Execute;
                } else {
                    self.state = RingState::BuildRing(n + 1);
                }
            }

            // Execute signing operation
            (RingState::Execute, Event::TxSign) => {
                // Finalise ring signing
                let (key_image, c_zero) = match self.ring_finalise() {
                    Ok(v) => v,
                    Err(e) => {
                        #[cfg(feature = "log")]
                        log::error!("ring sign failed: {:?}", e);

                        self.state = RingState::Error;
                        return Err(e);
                    }
                };

                // Save key image
                self.state = RingState::Complete {
                    key_image,
                    c_zero: c_zero.into(),
                };
            }

            // Fetch key_image and c_zero
            (RingState::Complete { key_image, c_zero }, Event::TxGetKeyImage) => {
                return Ok((self.state, Output::TxKeyImage { key_image, c_zero }))
            }

            // Fetch responses to reconstruct ring
            (RingState::Complete { .. }, Event::TxGetResponse { index }) => {
                let sign_ctx = match self.ring_ctx.as_ref() {
                    Some(v) => v,
                    None => return Err(Error::UnexpectedEvent),
                };

                let scalar = match sign_ctx.responses().and_then(|r| r.get(*index as usize)) {
                    Some(v) => (*v).into(),
                    None => return Err(Error::UnexpectedEvent),
                };

                // Update last index for progress indication
                self.fetch_count += 1;

                return Ok((
                    self.state,
                    Output::TxResponse {
                        ring_index: *index,
                        scalar,
                    },
                ));
            }
            _ => (),
        }

        Ok((self.state, Output::None))
    }

    /// Fetch ring progress (n / 100)
    pub fn progress(&self) -> usize {
        let ring_size = self.ring_size;

        let total = ring_size * 3 + 2;

        let index = match self.state {
            RingState::Init => 0,
            RingState::BuildRing(n) => 1 + n as usize,
            RingState::Execute => 1 + ring_size,
            RingState::Complete { .. } => 2 + ring_size + self.fetch_count,
            RingState::Error => 0,
        };

        if index == 0 || total == 0 {
            return 0;
        }

        index * 100 / total
    }

    /// Internal helper to setup MLSAG
    #[cfg_attr(feature = "noinline", inline(never))]
    fn ring_init(
        &mut self,
        real_txout: &ReducedTxOut,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(), Error> {
        // Check blindings are loaded
        let blindings = match &self.blindings {
            Some(b) => b,
            _ => return Err(Error::MissingBlindings),
        };

        // Extract public key for real txout
        let tx_out_public_key = match RistrettoPublic::try_from(&real_txout.public_key) {
            Ok(k) => k,
            Err(_e) => return Err(Error::InvalidKey),
        };
        // Extract target key for real txout
        let tx_out_target_key = match RistrettoPublic::try_from(&real_txout.target_key) {
            Ok(k) => k,
            Err(_e) => return Err(Error::InvalidKey),
        };

        // Recover onetime_private_key for real txout
        let mut onetime_private_key = recover_onetime_private_key(
            &tx_out_public_key,
            self.root_view_private.as_ref(),
            self.subaddress_spend_private.as_ref(),
        );

        // Check this is the correct onetime private key for the txout
        if RistrettoPublic::from(&onetime_private_key) != tx_out_target_key {
            // Zeroize recovered key on failure
            onetime_private_key.zeroize();
            return Err(Error::OnetimeKeyRecoveryFailed);
        }

        // Setup signing context
        let sign_params = MlsagSignParams {
            ring_size: self.ring_size,
            message: &self.message,
            real_index: self.real_index,
            onetime_private_key: &onetime_private_key,
            value: self.value,
            blinding: &blindings.blinding,
            output_blinding: &blindings.output_blinding,
            generator: &self.generator,
            check_value_is_preserved: true,
        };

        // Setup response storage, this _must_ be ring_size * 2 or init will fail
        // NOTE: switched to this approach to avoid miri complaints, costs us ~1.5k of stack but, we have the headroom on the nanosplus and nanox support requires the stack fix anyway.
        // TODO: work out whether we can push storage of this up to the global context to reduce stack use.
        let mut responses = heapless::Vec::<_, RESP_SIZE>::new();
        responses
            .resize(self.ring_size * 2, CurveScalar::default())
            .unwrap();

        match MlsagSignCtx::init(&sign_params, rng, responses) {
            Ok(ctx) => {
                // Store context
                self.onetime_private_key = Some(onetime_private_key);
                self.ring_ctx = Some(ctx);
            },
            Err(_e) => {
                // Clear onetime private key
                onetime_private_key.zeroize();
                // Fail out
                return Err(Error::RingInitFailed);
            }
        }

        Ok(())
    }

    /// Internal helper to update MLSAG
    #[cfg_attr(feature = "noinline", inline(never))]
    fn ring_update(&mut self, index: usize, tx_out: &ReducedTxOut) -> Result<(), Error> {
        // Check we have a signing context and blindings
        let ring_ctx = match self.ring_ctx.as_mut() {
            Some(v) => v,
            None => return Err(Error::UnexpectedEvent),
        };
        let blindings = match &self.blindings {
            Some(b) => b,
            _ => return Err(Error::MissingBlindings),
        };

        // Check onetime private key recovery has occurred
        let onetime_private_key = match &self.onetime_private_key {
            Some(k) => k,
            _ => return Err(Error::MissingOnetimePrivateKey),
        };

        let sign_params = MlsagSignParams {
            ring_size: self.ring_size,
            message: &self.message,
            real_index: self.real_index,
            onetime_private_key,
            value: self.value,
            blinding: &blindings.blinding,
            output_blinding: &blindings.output_blinding,
            generator: &self.generator,
            check_value_is_preserved: false,
        };

        // Decompress txout
        let tx_out = tx_out.try_into().map_err(|_| Error::UnexpectedEvent)?;

        // Add txout to ring
        ring_ctx
            .update(&sign_params, index, &tx_out)
            .map_err(|_e| Error::SignError)?;

        Ok(())
    }

    /// Internal helper to finalise MLSAG
    #[cfg_attr(feature = "noinline", inline(never))]
    fn ring_finalise(&mut self) -> Result<(KeyImage, CurveScalar), Error> {
        let ring_ctx = match self.ring_ctx.as_mut() {
            Some(v) => v,
            None => return Err(Error::UnexpectedEvent),
        };

        let blindings = match &self.blindings {
            Some(b) => b,
            _ => return Err(Error::UnexpectedEvent),
        };

        let onetime_private_key = match &self.onetime_private_key {
            Some(k) => k,
            _ => return Err(Error::UnexpectedEvent),
        };

        let sign_params = MlsagSignParams {
            ring_size: self.ring_size,
            message: &self.message,
            real_index: self.real_index,
            onetime_private_key,
            value: self.value,
            blinding: &blindings.blinding,
            output_blinding: &blindings.output_blinding,
            generator: &self.generator,
            // TODO: is this important..?
            check_value_is_preserved: false,
        };

        let (key_image, c_zero) = match ring_ctx.finalise(&sign_params) {
            Ok(v) => v,
            Err(_e) => {
                #[cfg(feature = "log")]
                log::error!("Ring signing failed: {:?}", _e);
                return Err(Error::SignError);
            }
        };

        Ok((key_image, c_zero))
    }
}

#[cfg(test)]
mod test {
    use core::mem::MaybeUninit;

    use rand_core::OsRng;

    use mc_core::{account::RingCtAddress, subaddress::Subaddress};
    use mc_crypto_ring_signature::{
        onetime_keys::recover_public_subaddress_spend_key, CompressedCommitment, MlsagVerify,
    };
    use mc_util_test_helper::{RngType, SeedableRng};

    use crate::engine::test::TestDriver;
    use ledger_mob_tests::mlsag::RingMLSAGParameters;

    use super::*;

    // `sign` should return a signature with correct key image.
    // see: [`mc_crypto_ring_signature::mlsag::mlsag_tests`]
    #[test]
    fn ring_sign() {
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

        // Setup ring signer
        let mut r = MaybeUninit::uninit();
        let mut ring_signer = unsafe {
            RingSigner::init(
                r.as_mut_ptr(),
                RING_SIZE,
                params.real_index,
                account.view_private_key(),
                account
                    .subaddress(params.target_subaddress_index)
                    .spend_private_key(),
                params.value,
                &params.message,
                params.token_id,
                None,
            )
            .unwrap();
            r.assume_init()
        };

        let progress_total = RING_SIZE * 3 + 2;

        // Set blindings
        let (_state, _) = ring_signer
            .update(
                &Event::TxSetBlinding {
                    blinding: params.blinding,
                    output_blinding: pseudo_output_blinding,
                },
                OsRng {},
            )
            .expect("Set blinding");

        // Load txouts into ring
        for n in 0..RING_SIZE {
            let i = (params.real_index + n) % RING_SIZE;
            let tx_out = &params.ring[i];

            assert_eq!(
                ring_signer.state,
                RingState::BuildRing(n as u8),
                "add txout {} invalid state: {:?}",
                i,
                ring_signer.state
            );

            let (state, _) = ring_signer
                .update(&Event::TxAddTxout(i as u8, tx_out.clone()), OsRng {})
                .expect("Failed to add txout");

            if n < RING_SIZE - 1 {
                assert_eq!(
                    state,
                    RingState::BuildRing(n as u8 + 1),
                    "add txout {n} failed (state: {state:?})"
                );
            } else {
                assert_eq!(
                    state,
                    RingState::Execute,
                    "add final txout {n} failed (state: {state:?})"
                );
            }

            let progress = ring_signer.progress();
            assert_eq!(
                progress,
                (n + 2) * 100 / progress_total,
                "invalid progress for iteration {n} / {progress_total} (state: {state:?})"
            );
        }

        // Generate signature
        let (_state, _output) = ring_signer
            .update(&Event::TxSign, OsRng {})
            .expect("Execute sign");

        assert_eq!(
            ring_signer.progress(),
            (RING_SIZE + 2) * 100 / progress_total
        );

        // Fetch key image
        let (_state, output) = ring_signer
            .update(&Event::TxGetKeyImage, OsRng {})
            .expect("Fetch key image");

        // Check ring state is complete and key image is valid
        let expected_key_image = KeyImage::from(&params.onetime_private_key);
        let (key_image, c_zero) = match output {
            Output::TxKeyImage { key_image, c_zero } => {
                assert_eq!(key_image, expected_key_image);
                (key_image, c_zero)
            }
            _ => panic!("unexpected output: {output:?}"),
        };

        // Fetch responses
        let mut responses = alloc::vec::Vec::new();

        for i in 0..RESP_SIZE {
            let (_state, output) = ring_signer
                .update(&Event::TxGetResponse { index: i as u8 }, OsRng {})
                .expect("Fetch response");

            let r = match output {
                Output::TxResponse {
                    ring_index: _,
                    scalar,
                } => scalar.into(),
                _ => panic!("Unexpected output: {output:?}"),
            };

            responses.push(r);

            assert_eq!(
                ring_signer.progress(),
                (RING_SIZE + i + 3) * 100 / progress_total
            );
        }

        assert_eq!(ring_signer.progress(), 100);

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
