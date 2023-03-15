// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Subaddress key tests

use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::info;
use std::future::Future;

use mc_core::{
    account::{Account, RingCtAddress},
    slip10::{Mnemonic, Slip10KeyGenerator},
    subaddress::Subaddress,
};

use ledger_transport::Exchange;

use ledger_mob::{DeviceHandle, Error};

/// Generate and fetch subaddress keys for the provided mnemonic
pub async fn test<T, F, E>(
    t: T,
    approve: impl Fn() -> F,
    mnemonic: Mnemonic,
    n: u64,
) -> anyhow::Result<()>
where
    T: Exchange<Error = E> + Send + Sync,
    F: Future<Output = ()>,
    Error: From<E>,
{
    info!("using mnemonic: '{}'", mnemonic.phrase());

    // Derive base key from seed
    let slip10key = mnemonic.derive_slip10_key(0);
    info!("slip10: {}", STANDARD.encode(&slip10key));

    let account_key = Account::from(&slip10key);

    let d = DeviceHandle::from(t);

    for index in 0..n {
        info!("fetch subaddress {}", index);

        let subaddr = account_key.subaddress(index);

        info!("expected view_private: '{}'", subaddr.view_private);
        info!("expected spend_public: '{}'", subaddr.spend_public_key());

        // Fetch wallet keys from device, handling approval UX
        let r = d.subaddress_keys(0, index).await;
        let r = match r {
            Ok(v) => v,
            // App requires approval
            Err(_) => {
                // Set approved
                approve().await;

                // Retry request (for some reason the simulator fails the first
                // time this is re-requested, though the device does not..?)
                let _ = d.subaddress_keys(0, index).await;

                d.subaddress_keys(0, index).await?
            }
        };

        info!("Response: {:02x?}", r);

        info!("received subaddress view_private: '{}'", r.view_private);
        info!("received subaddress spend_public: '{}'", r.spend_public);

        // Check wallet root keys match
        assert_eq!(r.view_private, subaddr.view_private);

        assert_eq!(r.spend_public, subaddr.spend_public_key(),);
    }

    Ok(())
}
