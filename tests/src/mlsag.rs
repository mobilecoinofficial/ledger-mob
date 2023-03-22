// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ring signature tests

use std::{future::Future, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{debug, info};
use rand_core::{CryptoRng, OsRng, RngCore};

use mc_core::{
    account::{Account, RingCtAddress},
    slip10::{Mnemonic, Slip10KeyGenerator},
    subaddress::Subaddress,
};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{
    generators,
    onetime_keys::{
        create_tx_out_public_key, create_tx_out_target_key, recover_onetime_private_key,
        recover_public_subaddress_spend_key,
    },
    CompressedCommitment, CurveScalar, KeyImage, MlsagSignParams, PedersenGens, ReducedTxOut,
    RingMLSAG, Scalar,
};
use mc_util_from_random::FromRandom;

use ledger_transport::Exchange;

use ledger_mob::Error;
use ledger_mob_apdu::{state::TxState, tx::*};

/// Start a transaction and sign a ring via [RingMLSAGParameters] object
pub async fn test<T, F>(
    t: T,
    approve: impl Fn() -> F,
    mnemonic: Mnemonic,
    ring_size: usize,
) -> anyhow::Result<()>
where
    T: Exchange<Error = Error>,
    F: Future<Output = ()>,
{
    let mut buff = [0u8; 256];

    debug!("using mnemonic: '{}'", mnemonic.phrase());

    // Derive base key from seed
    let slip10key = mnemonic.derive_slip10_key(0);
    info!("slip10: {}", STANDARD.encode(&slip10key));
    let account = Account::from(&slip10key);

    info!("MLSAG test start");

    // Setup MLSAG
    let pseudo_output_blinding = Scalar::random(&mut OsRng {});
    let params = RingMLSAGParameters::random(
        &account,
        ring_size - 1,
        pseudo_output_blinding,
        &mut OsRng {},
    );

    info!(
        "onetime_private_key: {}",
        hex::encode(params.onetime_private_key)
    );

    // Initialise transaction
    let tx_init = TxInit::new(0, 1);

    info!("Initialise transaction: {:?}", tx_init);
    let r = t.exchange::<TxInfo>(tx_init, &mut buff).await.unwrap();

    debug!("State: {:?}", r);
    assert_eq!(r.state, TxState::SignMemos);

    // TODO: sign any memos required

    // Set message for transaction
    let tx_set_message = TxSetMessage {
        message: &params.message,
    };
    info!("Set message: {:?}", tx_set_message);
    let r = t
        .exchange::<TxInfo>(tx_set_message, &mut buff)
        .await
        .unwrap();

    debug!("State: {:?}", r);
    assert_eq!(r.state, TxState::Pending);

    // Approve transaction (hooks to engine internals or UI)
    approve().await;

    // Fetch / await ready state
    let mut s = None;
    for _i in 0..10 {
        debug!("awaiting tx approval (state: {:?})", r);
        if let Ok(v) = t.exchange::<TxInfo>(TxInfoReq {}, &mut buff).await {
            s = Some(v.clone());

            if v.state == TxState::Ready {
                break;
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let r = s.unwrap();

    debug!("State: {:?}", r);
    assert_eq!(r.state, TxState::Ready);

    // Start ring signing
    let tx_ring_init = TxRingInit::new(
        ring_size as u8,
        params.real_index as u8,
        params.target_subaddress_index,
        params.value,
        params.token_id,
    );
    info!("Start ring signing: {:?}", tx_ring_init);
    let r = t.exchange::<TxInfo>(tx_ring_init, &mut buff).await.unwrap();

    debug!("State: {:?}", r);

    // Set blindings
    let tx_set_blinding = TxSetBlinding {
        blinding: params.blinding,
        output_blinding: pseudo_output_blinding,
    };
    info!("Set blindings: {:?}", tx_set_blinding);
    let r = t
        .exchange::<TxInfo>(tx_set_blinding, &mut buff)
        .await
        .unwrap();

    debug!("State: {:?}", r);

    info!("Loading {} txouts", params.ring.len());

    // Load txouts into ring
    for n in 0..ring_size {
        let i = (params.real_index + n) % ring_size;
        let tx_out = &params.ring[i];

        let tx_add_txout = TxAddTxOut::new(
            i as u8,
            tx_out.public_key,
            tx_out.target_key,
            CompressedRistrettoPublic::from(tx_out.commitment.point),
        );

        debug!("Add txout: {:?}", tx_add_txout);

        let r = t.exchange::<TxInfo>(tx_add_txout, &mut buff).await.unwrap();

        debug!("State: {:?}", r);
    }

    info!("Signing MLSAG");

    // Generate signature
    let r = t.exchange::<TxInfo>(TxRingSign, &mut buff).await.unwrap();
    assert_eq!(
        r.state,
        TxState::RingComplete,
        "expected ring signature complete"
    );

    // Retrieve key image
    let TxKeyImage { key_image, c_zero } = t
        .exchange::<TxKeyImage>(TxGetKeyImage {}, &mut buff)
        .await
        .unwrap();

    // Check key image is valid
    let expected_key_image = KeyImage::from(&params.onetime_private_key);
    assert_eq!(key_image, expected_key_image);

    // Fetch responses
    let mut responses = heapless::Vec::<CurveScalar, 22>::new();
    for i in 0..ring_size * 2 {
        let resp = t
            .exchange::<TxResponse>(TxGetResponse::new(i as u8), &mut buff)
            .await
            .unwrap();

        assert_eq!(resp.ring_index as usize, i);

        responses.push(CurveScalar::from(resp.scalar)).unwrap();
    }

    debug!("Responses: {:?}", responses);

    // Recover spend and onetime keys

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

    info!("Verifying ring");

    // Verify ring
    let ring = RingMLSAG {
        c_zero: c_zero.into(),
        responses: responses.to_vec(),
        key_image,
    };

    let output_commitment =
        CompressedCommitment::new(params.value, pseudo_output_blinding, &params.generator);

    ring.verify(&params.message, params.ring.as_slice(), &output_commitment)
        .expect("Failed to verify ring");

    info!("MLSAG TEST OK (key image: {})!", key_image);

    Ok(())
}

/// Copy 3 of RingMLSAGParameters... we should pull this out somewhere
#[derive(Debug)]
pub struct RingMLSAGParameters {
    pub message: [u8; 32],
    pub token_id: u64,
    pub ring: heapless::Vec<ReducedTxOut, 16>,
    pub real_index: usize,
    pub onetime_private_key: RistrettoPrivate,
    pub value: u64,
    pub blinding: Scalar,
    pub pseudo_output_blinding: Scalar,
    pub generator: PedersenGens,
    pub target_subaddress_index: u64,
}

impl RingMLSAGParameters {
    pub fn random<RNG: RngCore + CryptoRng>(
        account: &Account,
        num_mixins: usize,
        pseudo_output_blinding: Scalar,
        rng: &mut RNG,
    ) -> Self {
        let mut message = [0u8; 32];
        rng.fill_bytes(&mut message);

        let token_id = rng.next_u64();
        let generator = generators(token_id);

        let mut ring: heapless::Vec<ReducedTxOut, 16> = heapless::Vec::new();
        for _i in 0..num_mixins {
            let public_key = CompressedRistrettoPublic::from_random(rng);
            let target_key = CompressedRistrettoPublic::from_random(rng);
            let commitment = {
                let value = rng.next_u64();
                let blinding = Scalar::random(rng);
                CompressedCommitment::new(value, blinding, &generator)
            };
            let _ = ring.push(ReducedTxOut {
                public_key,
                target_key,
                commitment,
            });
        }

        let target_subaddress_index = rng.next_u64() % 100;
        let target_subaddr = account.subaddress(target_subaddress_index);

        // The real input.

        // tx_private_key is random input to tx
        // shared_secret kx for encryption / enabling view for both sides
        // onetime private key for _spending_ the txout

        // `r` for random derivation of other components
        let tx_private_key = RistrettoPrivate::from_random(rng);

        // TODO: shouldn't shared secret plug in here..? or is this already included in the create_tx_out_X methods.
        //let shared_secret = create_shared_secret(recipient.view_public_key(), tx_private_key);

        let value = rng.next_u64();
        let blinding = Scalar::random(rng);
        let commitment = CompressedCommitment::new(value, blinding, &generator);

        let tx_out_public =
            create_tx_out_public_key(&tx_private_key, target_subaddr.spend_public_key().as_ref());

        let tx_target_public = create_tx_out_target_key(&tx_private_key, &target_subaddr);

        let reduced_tx_out = ReducedTxOut {
            target_key: CompressedRistrettoPublic::from(&tx_target_public),
            public_key: CompressedRistrettoPublic::from(&tx_out_public),
            commitment,
        };

        // since this is a test case we have the target subaddress so are able to recover the onetime private key
        let onetime_private_key = recover_onetime_private_key(
            &tx_out_public,
            account.view_private_key().as_ref(),
            target_subaddr.spend_private_key().as_ref(),
        );

        assert_eq!(
            RistrettoPublic::from(&onetime_private_key),
            tx_target_public
        );

        let real_index = rng.next_u64() as usize % (num_mixins) + 1;
        let _ = ring.insert(real_index, reduced_tx_out);
        assert_eq!(ring.len(), num_mixins + 1);

        Self {
            message,
            token_id,
            ring,
            real_index,
            onetime_private_key,
            value,
            blinding,
            pseudo_output_blinding,
            generator,
            target_subaddress_index,
        }
    }

    pub fn sign(
        &self,
        rng: impl RngCore + CryptoRng,
        balance_check: bool,
    ) -> Result<RingMLSAG, Error> {
        let opts = MlsagSignParams {
            ring_size: self.ring.len(),
            message: &self.message,
            real_index: self.real_index,
            onetime_private_key: &self.onetime_private_key,
            value: self.value,
            blinding: &self.blinding,
            output_blinding: &self.pseudo_output_blinding,
            generator: &self.generator,
            check_value_is_preserved: balance_check,
        };

        let mut responses = vec![CurveScalar::default(); self.ring.len()];

        let (key_image, c_zero) = opts.sign(&self.ring[..], rng, &mut responses)?;

        Ok(RingMLSAG {
            c_zero,
            responses,
            key_image,
        })
    }
}

#[cfg(test)]
mod test {
    use mc_crypto_ring_signature::CompressedCommitment;
    use mc_util_test_helper::{RngType, SeedableRng};

    use super::*;

    #[test]
    // `sign` should return a signature with correct key image.
    fn test_sign_produces_correct_key_image() {
        let seed = [0u8; 32];
        let mut rng: RngType = SeedableRng::from_seed(seed);
        let pseudo_output_blinding = Scalar::random(&mut rng);

        let account = Account::new(
            RistrettoPrivate::from_random(&mut rng).into(),
            RistrettoPrivate::from_random(&mut rng).into(),
        );

        let params = RingMLSAGParameters::random(&account, 10, pseudo_output_blinding, &mut rng);

        let signature = params.sign(&mut rng, true).unwrap();

        let expected_key_image = KeyImage::from(&params.onetime_private_key);
        assert_eq!(signature.key_image, expected_key_image);
    }

    #[test]
    // `verify` should accept valid signatures.
    fn test_verify_accepts_valid_signatures() {
        let _ = simplelog::SimpleLogger::init(log::LevelFilter::Debug, Default::default());

        let seed = [0u8; 32];
        let mut rng: RngType = SeedableRng::from_seed(seed);
        let pseudo_output_blinding = Scalar::random(&mut rng);

        let account = Account::new(
            RistrettoPrivate::from_random(&mut rng).into(),
            RistrettoPrivate::from_random(&mut rng).into(),
        );

        let params = RingMLSAGParameters::random(&account, 10, pseudo_output_blinding, &mut rng);

        let signature = params.sign(&mut rng, true).unwrap();

        let output_commitment = CompressedCommitment::new(
            params.value,
            params.pseudo_output_blinding,
            &params.generator,
        );

        assert!(signature
            .verify(&params.message, &params.ring[..], &output_commitment)
            .is_ok());
    }

    #[test]
    // target should be able to match on view key
    fn test_view_key_match() {
        let seed = [0u8; 32];
        let mut rng: RngType = SeedableRng::from_seed(seed);
        let pseudo_output_blinding = Scalar::random(&mut rng);

        let account = Account::new(
            RistrettoPrivate::from_random(&mut rng).into(),
            RistrettoPrivate::from_random(&mut rng).into(),
        );

        let params = RingMLSAGParameters::random(&account, 10, pseudo_output_blinding, &mut rng);

        // TODO: see `transaction/core/src/tx.rs`:429

        let _signature = params.sign(&mut rng, true).unwrap();
    }
}
