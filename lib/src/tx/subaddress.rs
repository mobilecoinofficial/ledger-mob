// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Subaddress API

use futures::executor::block_on;
use log::debug;

use ledger_mob_apdu::subaddress_keys::{SubaddressKeyReq, SubaddressKeyResp};
use mc_core::{account::ViewSubaddress, subaddress::Subaddress};

use ledger_lib::Device;

use super::{Error, TransactionHandle};

/// Sync [Subaddress] implementation for [TransactionHandle]
///
/// Note: this MUST be called from a tokio context
impl<T: Device> Subaddress for TransactionHandle<T> {
    type Output = Result<ViewSubaddress, Error>;

    /// Fetch view subaddress by subaddress index,
    /// inheriting the account index from the transaction context.
    fn subaddress(&self, index: u64) -> Self::Output {
        tokio::task::block_in_place(|| block_on(async { self.view_subaddress(index).await }))
    }
}

impl<T: Device> TransactionHandle<T> {
    /// Asynchronously fetch a view subaddress by subaddress index,
    /// inheriting the account index from the transaction context.
    ///
    /// See [Subaddress] trait for public (blocking) API
    pub async fn view_subaddress(&self, index: u64) -> Result<ViewSubaddress, Error> {
        debug!("Fetching view subaddress keys for index: {}", index);

        let mut buff = [0u8; 256];
        let req = SubaddressKeyReq::new(self.info.account_index, index);

        let mut t = self.t.lock().await;

        let resp = t
            .request::<SubaddressKeyResp>(req, &mut buff, self.info.request_timeout)
            .await?;

        Ok(ViewSubaddress {
            view_private: resp.view_private,
            spend_public: resp.spend_public,
        })
    }
}
