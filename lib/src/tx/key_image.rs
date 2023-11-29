// Copyright (c) 2022-2023 The MobileCoin Foundation

use std::time::Duration;

use futures::executor::block_on;
use log::debug;

use ledger_lib::Device;
use ledger_mob_apdu::key_image::{KeyImageReq, KeyImageResp};

use mc_core::keys::TxOutPublic;
use mc_crypto_ring_signature::KeyImage;
use mc_transaction_signer::traits::KeyImageComputer;

use crate::{tx::TransactionHandle, Error};

/// Sync [KeyImageComputer] implementation for [TransactionHandle]
///
/// Note: this MUST be called from a tokio context
impl<T: Device> KeyImageComputer for TransactionHandle<T> {
    type Error = Error;

    /// Compute key image for a given subaddress and tx_out_public_key
    fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &TxOutPublic,
    ) -> Result<KeyImage, Self::Error> {
        tokio::task::block_in_place(|| {
            block_on(async { self.key_image(subaddress_index, tx_out_public_key).await })
        })
    }
}

impl<T: Device> TransactionHandle<T> {
    /// Asynchronously compute key image for a given subaddress and
    /// tx_out_public_key.
    ///
    /// See [KeyImageComputer] for the public blocking API
    pub async fn key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &TxOutPublic,
    ) -> Result<KeyImage, Error> {
        let mut buff = [0u8; 256];

        let mut t = self.t.lock().await;

        debug!(
            "Resolving key image for account: {} subaddress: {} tx_out_public: {}",
            self.info.account_index, subaddress_index, tx_out_public_key
        );
        let req = KeyImageReq::new(
            self.info.account_index,
            subaddress_index,
            tx_out_public_key.clone(),
        );
        let resp = t
            .request::<KeyImageResp>(req, &mut buff, Duration::from_secs(1))
            .await?;

        Ok(resp.key_image)
    }
}
