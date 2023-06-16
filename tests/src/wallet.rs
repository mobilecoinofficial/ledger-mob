// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Account key tests

use std::future::Future;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tracing::info;

use mc_core::{
    account::Account,
    slip10::{Mnemonic, Slip10KeyGenerator},
};

use ledger_lib::Device;

use ledger_mob::DeviceHandle;

/// Generate and fetch account view keys for the provided mnemonic
pub async fn test<T, F>(t: T, approve: impl Fn() -> F, mnemonic: Mnemonic) -> anyhow::Result<()>
where
    T: Device + Send,
    F: Future<Output = ()>,
{
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Generate expected wallet keys

    // Derive base key from seed
    let slip10key = mnemonic.derive_slip10_key(0);
    info!("slip10: {}", STANDARD.encode(&slip10key));

    let account_key = Account::from(&slip10key);

    info!(
        "expected view_private: '{}'",
        account_key.view_private_key()
    );
    info!(
        "expected spend_public: '{}'",
        account_key.spend_public_key()
    );

    let mut d = DeviceHandle::from(t);

    // Fetch account keys from device
    let a = match d.account_keys(0).await {
        Ok(v) => v,
        // App requires approval
        Err(_) => {
            // Set approved
            approve().await;

            // Retry request (for some reason the simulator fails the first
            // time this is re-requested, though the device does not..?)
            let _ = d.account_keys(0).await;

            d.account_keys(0).await?
        }
    };

    info!("received view_public: '{}'", a.view_private_key());
    info!("received spend_public: '{}'", a.spend_public_key());

    // Check wallet root keys match
    assert_eq!(&a.view_private_key(), &account_key.view_private_key());

    assert_eq!(a.spend_public_key(), &account_key.spend_public_key());

    Ok(())
}
