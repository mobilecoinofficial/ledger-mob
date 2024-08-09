// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ring signing API
//!
//!

use futures::executor::block_on;
use log::{debug, info};
use rand_core::CryptoRngCore;

use ledger_lib::Device;

use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature::{CurveScalar, RingMLSAG, Scalar};
use mc_crypto_ring_signature_signer::{
    Error as SignerError, OneTimeKeyDeriveData, RingSigner, SignableInputRing,
};

use ledger_mob_apdu::{state::TxState, tx::*};

use crate::tx::check_state;

use super::{Error, TransactionHandle};

/// Sync [RingSigner] implementation for [TransactionHandle]
///
/// Note: this MUST be called from a tokio context
impl<T: Device> RingSigner for TransactionHandle<T> {
    /// Execute ring signing operation on ledger hw
    fn sign(
        &self,
        message: &[u8],
        signable_ring: &SignableInputRing,
        pseudo_output_blinding: Scalar,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<RingMLSAG, SignerError> {
        // Wrap async to avoid hefty codebase changes
        tokio::task::block_in_place(|| {
            block_on(async {
                self.ring_sign(message, signable_ring, pseudo_output_blinding)
                    .await
            })
            .map_err(|e| {
                // TODO: convert signer errors back from ledger error types
                log::error!("Ring signer error: {:?}", e);
                SignerError::Unknown
            })
        })
    }
}

impl<T: Device> TransactionHandle<T> {
    /// Asynchronously execute a ring signing operation on ledger hardware.
    ///  
    /// See [RingSigner] trait for public / blocking API
    pub async fn ring_sign(
        &self,
        // TODO: message is per-transaction, not per-ring
        _message: &[u8],
        signable_ring: &SignableInputRing,
        pseudo_output_blinding: Scalar,
    ) -> Result<RingMLSAG, Error> {
        let mut buff = [0u8; 256];

        let mut t = self.t.lock().await;

        let ring_size = signable_ring.members.len();
        let real_index = signable_ring.real_input_index;

        // Handle unsigned and pre-signed rings
        let (subaddress_index, onetime_key) =
            match signable_ring.input_secret.onetime_key_derive_data {
                OneTimeKeyDeriveData::OneTimeKey(key) => (0, Some(key.into())),
                OneTimeKeyDeriveData::SubaddressIndex(i) => (i, None),
            };

        // TODO: Check we're ready to sign a ring

        debug!("Start ring signing...");

        // Start ring signing
        let tx_init = TxRingInit::new(
            signable_ring.members.len() as u8,
            signable_ring.real_input_index as u8,
            subaddress_index,
            signable_ring.input_secret.amount.value,
            *signable_ring.input_secret.amount.token_id,
            onetime_key,
        );
        let r = t
            .request::<TxInfo>(tx_init, &mut buff, self.info.request_timeout)
            .await?;

        // TODO: onetime_private_key looks to be per-ring?
        // (must be to correlate with real_input.target_key..?)

        debug!("Ring state: {:?}", r);

        debug!("Set blindings");

        // Set blindings
        let tx_set_blinding = TxSetBlinding {
            blinding: signable_ring.input_secret.blinding,
            output_blinding: pseudo_output_blinding,
        };
        let r = t
            .request::<TxInfo>(tx_set_blinding, &mut buff, self.info.request_timeout)
            .await?;

        debug!("Ring state: {:?}", r);

        info!("Loading {} txouts", ring_size);

        // Load txouts into ring
        for n in 0..ring_size {
            let i = (real_index + n) % ring_size;
            let tx_out = &signable_ring.members[i];

            let tx_add_txout = TxAddTxOut::new(
                i as u8,
                tx_out.public_key,
                tx_out.target_key,
                CompressedRistrettoPublic::from(tx_out.commitment.point),
            );

            let r = t
                .request::<TxInfo>(tx_add_txout, &mut buff, self.info.request_timeout)
                .await?;

            debug!("State: {:?}", r);
        }

        info!("Signing ring");

        // Generate signature
        let r = t
            .request::<TxInfo>(TxRingSign, &mut buff, self.info.request_timeout)
            .await?;
        check_state(r.state, TxState::RingComplete)?;

        debug!("Requesting key image");

        // Retrieve key image
        let TxKeyImage { key_image, c_zero } = t
            .request::<TxKeyImage>(TxGetKeyImage {}, &mut buff, self.info.request_timeout)
            .await?;

        debug!("Key image: {} c_zero: {:?}", key_image, c_zero);

        debug!("Requesting responses");

        // TODO: Check key image matches expectations for onetime private key?

        // Fetch responses
        let mut responses = Vec::<CurveScalar>::new();
        for i in 0..ring_size * 2 {
            debug!("Requesting response {}", i);

            let resp = t
                .request::<TxResponse>(
                    TxGetResponse::new(i as u8),
                    &mut buff,
                    self.info.request_timeout,
                )
                .await
                .unwrap();

            debug!("Response {}: {:?}", resp.ring_index, resp.scalar);

            if resp.ring_index as usize != i {
                return Err(Error::UnexpectedResponse);
            }

            responses.push(CurveScalar::from(resp.scalar));
        }

        // Reconstruct signed ring
        let ring = RingMLSAG {
            c_zero: CurveScalar::from(c_zero),
            responses,
            key_image,
        };

        // Update ring count
        {
            let mut state = self.state.borrow_mut();
            state.ring_count += 1;
        }

        Ok(ring)
    }
}
