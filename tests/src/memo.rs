// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Memo signing tests

use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{debug, info};
use mc_crypto_memo_mac::compute_category1_hmac;
use rand_core::{OsRng, RngCore};

use mc_core::{
    account::{Account, RingCtAddress},
    consts::DEFAULT_SUBADDRESS_INDEX,
    slip10::{Mnemonic, Slip10KeyGenerator},
    subaddress::Subaddress,
};
use mc_crypto_keys::{CompressedRistrettoPublic, KexReusablePrivate, RistrettoPrivate};
use mc_crypto_ring_signature::onetime_keys::create_tx_out_public_key;
use mc_util_from_random::FromRandom;

use ledger_transport::Exchange;

use ledger_mob_apdu::tx::*;

/// Test memo HMAC signing and verification
pub async fn hmac<T, E>(t: T, mnemonic: Mnemonic, _ring_size: usize) -> anyhow::Result<()>
where
    T: Exchange<Error = E>,
    E: std::error::Error + Sync + Send + 'static,
{
    let mut buff = [0u8; 256];

    debug!("using mnemonic: '{}'", mnemonic.phrase());

    // Derive base key from seed
    let slip10key = mnemonic.derive_slip10_key(0);
    info!("slip10: {}", STANDARD.encode(&slip10key));
    let account = Account::from(&slip10key);
    let sender_subaddr = account.subaddress(DEFAULT_SUBADDRESS_INDEX);

    info!("MEMO sign test start");

    // Setup fake transaction and target
    let onetime_private_key = RistrettoPrivate::from_random(&mut OsRng {});

    let target = Account::new(
        RistrettoPrivate::from_random(&mut OsRng {}).into(),
        RistrettoPrivate::from_random(&mut OsRng {}).into(),
    );
    let target_subaddr = target.subaddress(10);

    // Derive txout_public_key from onetime_private_key and target subaddress
    let tx_out_public_key = create_tx_out_public_key(
        &onetime_private_key,
        target_subaddr.spend_public_key().as_ref(),
    );

    // Initialise transaction
    debug!("Initialise transaction");
    let tx_init = TxInit::new(0, 1);
    let r = t.exchange::<TxInfo>(tx_init, &mut buff).await.unwrap();

    debug!("State: {:?}", r);

    // Sign memo
    let mut payload = [0u8; 48];
    OsRng {}.fill_bytes(&mut payload);

    let tx_memo_sign = TxMemoSign::new(
        DEFAULT_SUBADDRESS_INDEX,
        tx_out_public_key.into(),
        &target_subaddr,
        [0, 1],
        payload,
    );

    debug!("Request memo sign");
    let r = t
        .exchange::<TxMemoSig>(tx_memo_sign, &mut buff)
        .await
        .unwrap();

    // Reverse KX using receiver subaddress spend private and sender subaddress view public
    let target_view_private: &RistrettoPrivate = target_subaddr.view_private_key().as_ref();
    let sender_spend_public = sender_subaddr.spend_public_key();
    let shared_secret = target_view_private.key_exchange(sender_spend_public.as_ref());

    // Re-compute HMAC
    let hmac_value = compute_category1_hmac(
        shared_secret.as_ref(),
        &CompressedRistrettoPublic::from(&tx_out_public_key),
        [0, 1],
        &payload,
    );

    // Check values match
    assert_eq!(hmac_value, r.hmac);

    Ok(())
}
