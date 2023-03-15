// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Memo signing API
//!
//!

use futures::executor::block_on;
use ledger_mob_apdu::{
    state::TxState,
    tx::{TxMemoSig, TxMemoSign},
};
use ledger_transport::Exchange;

use mc_core::{account::PublicSubaddress, keys::TxOutPublic};
use mc_transaction_signer::traits::MemoHmacSigner;

use super::{check_digest, check_state, Error, TransactionContext, TransactionHandle};

impl<T: Exchange<Error = Error> + Send + Sync> MemoHmacSigner for TransactionHandle<T> {
    type Error = Error;

    /// Compute the HMAC signature for the provided memo and target address
    fn compute_memo_hmac_sig(
        &self,
        sender_subaddress_index: u64,
        tx_public_key: &TxOutPublic,
        target_subaddress: PublicSubaddress,
        memo_type: &[u8; 2],
        memo_data_sans_hmac: &[u8; 48],
    ) -> Result<[u8; 16], Self::Error> {
        tokio::task::block_in_place(|| {
            block_on(async {
                let mut ctx = self.ctx.lock().await;
                ctx.memo_sign(
                    sender_subaddress_index,
                    tx_public_key,
                    target_subaddress,
                    memo_type,
                    memo_data_sans_hmac,
                )
                .await
            })
        })
    }
}

impl<T: Exchange<Error = Error> + Send + Sync> TransactionContext<T> {
    /// Asynchronously compute the HMAC signature for the provided memo
    /// and target address.
    ///
    /// See [MemoHmacSigner] for the public blocking API.
    pub async fn memo_sign(
        &mut self,
        sender_subaddress_index: u64,
        tx_public_key: &TxOutPublic,
        target_subaddress: PublicSubaddress,
        memo_type: &[u8; 2],
        memo_data_sans_hmac: &[u8; 48],
    ) -> Result<[u8; 16], Error> {
        let mut buff = [0u8; 256];

        // TODO: device state has tx_out_private_key,
        // other memo keys recoverable from target_subaddress,
        // though this doesn't match proposed API?

        // TODO: check transaction / engine state is correct for memo signing

        // Build memo signing request
        let tx_memo_sign = TxMemoSign::new(
            sender_subaddress_index,
            tx_public_key.clone(),
            &target_subaddress,
            *memo_type,
            *memo_data_sans_hmac,
        );

        // Update transaction digest
        self.digest.update(&tx_memo_sign.hash());

        // Execute memo signing
        let r = self.exchange::<TxMemoSig>(tx_memo_sign, &mut buff).await?;

        // Check state and expected digest
        check_state::<T>(r.state, TxState::SignMemos)?;
        check_digest::<T>(&r.digest, &self.digest)?;

        // Update submitted memo count
        self.memo_count += 1;

        Ok(r.hmac)
    }
}
