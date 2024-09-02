// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Memo signing API
//!
//!

use futures::executor::block_on;
use ledger_lib::Device;
use ledger_mob_apdu::{
    state::{Digest, TxState},
    tx::{TxMemoSig, TxMemoSign},
};

use mc_core::{account::PublicSubaddress, keys::TxOutPublic};
use mc_transaction_signer::traits::MemoHmacSigner;

use super::{check_digest, check_state, Error, TransactionHandle};

/// Sync [MemoHmacSigner] implementation for [TransactionHandle]
///
/// Note: this MUST be called from a tokio context
impl<T: Device> MemoHmacSigner for TransactionHandle<T> {
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
                self.memo_sign(
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

impl<T: Device> TransactionHandle<T> {
    /// Asynchronously compute the HMAC signature for the provided memo
    /// and target address.
    ///
    /// See [MemoHmacSigner] for the public blocking API.
    pub async fn memo_sign(
        &self,
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

        let mut t = self.t.lock().await;

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
        let digest = {
            let mut state = self.state.borrow_mut();
            Digest::update(&mut state.digest, &tx_memo_sign.hash()).clone()
        };

        // Execute memo signing
        let r = t
            .request::<TxMemoSig>(tx_memo_sign, &mut buff, self.info.request_timeout)
            .await?;

        // Check state and expected digest
        check_state(r.state, TxState::SignMemos)?;
        check_digest(&r.digest, &digest)?;

        // Update submitted memo count
        {
            let mut state = self.state.borrow_mut();
            state.memo_count += 1;
        }

        Ok(r.hmac)
    }
}
