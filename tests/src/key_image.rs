// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Key image tests

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mc_crypto_ring_signature::onetime_keys::{
    create_tx_out_public_key, create_tx_out_target_key, recover_onetime_private_key,
};
use rand_core::OsRng;
use tracing::info;

use mc_core::{
    account::{Account, RingCtAddress},
    slip10::{Mnemonic, Slip10KeyGenerator},
    subaddress::Subaddress,
};
use mc_crypto_keys::RistrettoPrivate;
use mc_crypto_ring_signature::KeyImage;
use mc_util_from_random::FromRandom;

use ledger_lib::Device;

use ledger_mob::DeviceHandle;

/// Test key image recovery via subaddress and tx_out_public_key
pub async fn test<T>(t: T, mnemonic: Mnemonic) -> anyhow::Result<()>
where
    T: Device + Send,
{
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Generate expected wallet keys

    // Derive base key from seed
    let slip10key = mnemonic.derive_slip10_key(0);
    info!("slip10: {}", STANDARD.encode(&slip10key));
    let account_key = Account::from(&slip10key);

    let subaddress_index = 102;
    let target_subaddr = account_key.subaddress(subaddress_index);

    let mut d = DeviceHandle::from(t);

    // Synthesize transaction for key image recovery

    let tx_private_key = RistrettoPrivate::from_random(&mut OsRng {});

    let tx_out_public =
        create_tx_out_public_key(&tx_private_key, target_subaddr.spend_public_key().as_ref());

    let _tx_target_key = create_tx_out_target_key(&tx_private_key, &target_subaddr);

    info!("tx_out_public: {:?}", tx_out_public);

    let onetime_private_key = recover_onetime_private_key(
        &tx_out_public,
        account_key.view_private_key().as_ref(),
        target_subaddr.spend_private_key().as_ref(),
    );

    info!("expected tx_private_key: '{:?}'", onetime_private_key);

    // Resolve tx_private_key subaddress_index device
    let key_image = d.key_image(0, subaddress_index, tx_out_public).await?;

    info!("received key_image: '{:?}'", key_image);

    // Check key images match
    assert_eq!(key_image, KeyImage::from(&onetime_private_key),);

    Ok(())
}
