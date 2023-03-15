// Copyright (c) 2022-2023 The MobileCoin Foundation

use futures::executor::block_on;
use log::debug;

use ledger_mob_apdu::key_image::{KeyImageReq, KeyImageResp};
use ledger_transport::Exchange;

use mc_core::keys::TxOutPublic;
use mc_crypto_ring_signature::KeyImage;
use mc_transaction_signer::traits::KeyImageComputer;

use crate::{Error, TransactionHandle};

use super::TransactionContext;

impl<T: Exchange<Error=Error> + Send + Sync> KeyImageComputer for TransactionHandle<T> {
    type Error = Error;

    /// Compute key image for a given subaddress and tx_out_public_key
    fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &TxOutPublic,
    ) -> Result<KeyImage, Self::Error> {
        tokio::task::block_in_place(|| {
            block_on(async {
                let mut ctx = self.ctx.lock().await;
                ctx.key_image(subaddress_index, tx_out_public_key).await
            })
        })
    }
}

impl<T: Exchange<Error=Error> + Send + Sync> TransactionContext<T>
{
    /// Asynchronously compute key image for a given subaddress and
    /// tx_out_public_key.
    ///
    /// See [KeyImageComputer] for the public blocking API
    pub async fn key_image(
        &mut self,
        subaddress_index: u64,
        tx_out_public_key: &TxOutPublic,
    ) -> Result<KeyImage, Error> {
        let mut buff = [0u8; 256];

        debug!(
            "Resolving key image for account: {} subaddress: {} tx_out_public: {}",
            self.info.account_index, subaddress_index, tx_out_public_key
        );
        let req = KeyImageReq::new(
            self.info.account_index,
            subaddress_index,
            tx_out_public_key.clone(),
        );
        let resp = self.exchange::<KeyImageResp>(req, &mut buff).await?;

        Ok(resp.key_image)
    }
}
