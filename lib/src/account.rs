//! [AccountHandle] for account-based operations

// Copyright (c) 2022-2023 The MobileCoin Foundation

use std::{sync::Arc, time::Duration};

use futures::executor::block_on;
use ledger_lib::Device;
use log::debug;
use tokio::sync::Mutex;

use ledger_mob_apdu::{
    key_image::{KeyImageReq, KeyImageResp},
    wallet_keys::{WalletKeyReq, WalletKeyResp},
};

use mc_core::account::ViewAccount;
use mc_crypto_ring_signature::KeyImage;
use mc_transaction_signer::traits::{KeyImageComputer, ViewAccountProvider};

use crate::Error;

/// Handle to a hardware wallet configured with an account index
///
/// See [DeviceHandle::account][super::DeviceHandle::account] to
/// create a [AccountHandle]
#[derive(Clone)]
pub struct AccountHandle<T: Device> {
    pub(crate) account_index: u32,
    pub(crate) user_timeout: Duration,
    pub(crate) t: Arc<Mutex<T>>,
}

impl<T: Device> AccountHandle<T> {}

impl<T: Device> KeyImageComputer for AccountHandle<T> {
    type Error = Error;

    fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &mc_core::keys::TxOutPublic,
    ) -> Result<KeyImage, Self::Error> {
        let mut buff = [0u8; 256];

        let account_index = self.account_index;
        let timeout = self.user_timeout;
        let t = self.t.clone();

        tokio::task::block_in_place(|| {
            block_on(async {
                debug!(
                    "Resolving key image for account: {}, subaddress: {}, tx_public_key: {}",
                    account_index, subaddress_index, tx_out_public_key
                );

                let req =
                    KeyImageReq::new(account_index, subaddress_index, tx_out_public_key.clone());
                let resp = t
                    .lock()
                    .await
                    .request::<KeyImageResp>(req, &mut buff, timeout)
                    .await?;

                Ok(resp.key_image)
            })
        })
    }
}

impl<T: Device> ViewAccountProvider for AccountHandle<T> {
    type Error = Error;

    fn account(&self) -> Result<ViewAccount, Self::Error> {
        let mut buff = [0u8; 256];

        let account_index = self.account_index;
        let timeout = self.user_timeout;
        let t = self.t.clone();

        tokio::task::block_in_place(|| {
            block_on(async {
                debug!("Requesting root keys for account: {}", account_index);

                let req = WalletKeyReq::new(account_index);
                let resp = t
                    .lock()
                    .await
                    .request::<WalletKeyResp>(req, &mut buff, timeout)
                    .await?;

                Ok(ViewAccount::new(resp.view_private, resp.spend_public))
            })
        })
    }
}
