// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Subaddress API

use futures::executor::block_on;
use log::debug;

use ledger_mob_apdu::subaddress_keys::{SubaddressKeyReq, SubaddressKeyResp};
use mc_core::{account::ViewSubaddress, subaddress::Subaddress};

use ledger_transport::Exchange;

use crate::{Error, TransactionHandle};

// -technically- you should be able to implement `mc_core::Subaddress` with an
// `Output` type that impls Future, but, it raises some Big Lifetime Problems
// that i haven't been able to work out in a reasonable manner

impl<T: Exchange<Error = Error> + Send + Sync> Subaddress for TransactionHandle<T> {
    type Output = Result<ViewSubaddress, Error>;

    /// Fetch view subaddress by subaddress index,
    /// inheriting the account index from the transaction context.
    fn subaddress(&self, index: u64) -> Self::Output {
        tokio::task::block_in_place(|| block_on(async { self.view_subaddress(index).await }))
    }
}

impl<T: Exchange<Error = Error> + Send + Sync> TransactionHandle<T> {
    /// Asynchronously fetch a view subaddress by subaddress index,
    /// inheriting the account index from the transaction context.
    ///
    /// See [Subaddress] trait for public (blocking) API
    pub async fn view_subaddress(&self, index: u64) -> Result<ViewSubaddress, Error> {
        debug!("Fetching view subaddress keys for index: {}", index);

        let ctx = self.ctx.lock().await;

        let mut buff = [0u8; 256];
        let req = SubaddressKeyReq::new(ctx.info.account_index, index);

        let resp = ctx.exchange::<SubaddressKeyResp>(req, &mut buff).await?;

        Ok(ViewSubaddress {
            view_private: resp.view_private,
            spend_public: resp.spend_public,
        })
    }
}
