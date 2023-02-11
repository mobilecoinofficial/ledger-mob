// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Transaction APIs
//!
//!

use log::debug;
use std::{sync::Arc, time::Duration};

use tokio::sync::Mutex;

use ledger_apdu::{ApduBase, ApduCmd};
use ledger_mob_apdu::{
    state::{Digest, TxState},
    tx::{TxComplete, TxInfo, TxInfoReq, TxInit, TxSetMessage},
};
use ledger_transport::Exchange;

use crate::Error;

mod key_image;

mod memo;

mod ring;

mod subaddress;

mod summary;

/// Handle to a hardware wallet configured for transaction execution
///
/// See [DeviceHandle::transaction][super::DeviceHandle::transaction] to
/// create a [TransactionHandle]
#[derive(Clone)]
pub struct TransactionHandle<T: Exchange + Sync + Send> {
    ctx: Arc<Mutex<TransactionContext<T>>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TxConfig {
    /// Account index for key derivation
    pub account_index: u32,

    /// Number of memos
    pub num_memos: usize,

    /// Number of rings
    pub num_rings: usize,
}

struct TransactionContext<T: Exchange + Sync + Send> {
    t: T,

    /// General transaction configuration
    info: TxConfig,

    /// Digest computed over transaction inputs
    digest: Digest,

    /// Number of memos
    memo_count: usize,

    /// Number of rings
    ring_count: usize,
}

//unsafe impl<T: Exchange + Send + Sync> Send for TransactionHandle<T> {}

impl<T: Exchange + Send + Sync> TransactionHandle<T> {
    /// Initialise a new transaction
    pub(crate) async fn init(
        info: TxConfig,
        transport: T,
    ) -> Result<Self, Error<<T as Exchange>::Error>> {
        let mut buff = [0u8; 256];

        // Setup transaction
        let tx_init = TxInit::new(info.account_index, info.num_rings as u8);
        let r = transport
            .exchange::<TxInfo>(tx_init, &mut buff)
            .await
            .map_err(Error::Transport)?;

        //Self::check_state(r.state, TxState::Init)?;

        // Return transaction handle
        Ok(Self {
            ctx: Arc::new(Mutex::new(TransactionContext {
                info,
                t: transport,
                digest: r.digest,
                ring_count: 0,
                memo_count: 0,
            })),
        })
    }

    /// Set message for transaction
    pub async fn set_message(&self, m: &[u8]) -> Result<(), Error<<T as Exchange>::Error>> {
        let mut buff = [0u8; 256];
        let mut ctx = self.ctx.lock().await;

        // Build request
        let req = TxSetMessage::new(m);

        // Update transaction digest
        ctx.digest.update(&req.hash());

        // Issue request
        let resp = ctx.exchange::<TxInfo>(req, &mut buff).await?;

        // Check state and expected digest
        check_state::<T>(resp.state, TxState::Pending)?;
        check_digest::<T>(&resp.digest, &ctx.digest)?;

        Ok(())
    }

    /// Await on-device transaction approval
    pub async fn await_approval(
        &self,
        timeout_s: u32,
    ) -> Result<(), Error<<T as Exchange>::Error>> {
        let mut buff = [0u8; 256];
        let ctx = self.ctx.lock().await;

        for _i in 0..timeout_s {
            // Issue TxInfo request
            let r = ctx.exchange::<TxInfo>(TxInfoReq {}, &mut buff).await;

            debug!("awaiting tx approval (state: {:?})", r);

            // Handle responses, waiting for `Ready` or `Error` states
            match r {
                Ok(v) if v.state == TxState::Ready => return Ok(()),
                Ok(v) if v.state == TxState::Error => return Err(Error::Engine(0)),
                _ => (),
            }

            // Sleep while we wait
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Err(Error::UserTimeout)
    }

    /// Signal transaction completion
    pub async fn complete(self) -> Result<(), Error<<T as Exchange>::Error>> {
        let mut buff = [0u8; 256];
        let ctx = self.ctx.lock().await;

        let _r = ctx.exchange::<TxInfo>(TxComplete, &mut buff).await?;

        Ok(())
    }
}

/// Helper to check state when executing transactions
pub(crate) fn check_state<T: Exchange>(
    actual: TxState,
    expected: TxState,
) -> Result<(), Error<<T as Exchange>::Error>> {
    if actual != expected {
        Err(Error::InvalidState(actual, expected))
    } else {
        Ok(())
    }
}

/// Helper to check digest when executing transactions
pub(crate) fn check_digest<T: Exchange>(
    actual: &Digest,
    expected: &Digest,
) -> Result<(), Error<<T as Exchange>::Error>> {
    if expected != actual {
        Err(Error::DigestMismatch)
    } else {
        Ok(())
    }
}

/// Exchange impl on transaction context
impl<T: Exchange + Send + Sync> TransactionContext<T> {
    /// Helper for executing transactions with the device
    pub(crate) async fn exchange<'b, 'c, R: ApduBase<'b>>(
        &self,
        req: impl ApduCmd<'c>,
        buff: &'b mut [u8],
    ) -> Result<R, Error<<T as Exchange>::Error>> {
        // Execute exchange with internal timeout
        match tokio::time::timeout(Duration::from_secs(2), self.t.exchange(req, buff)).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(Error::Transport(e)),
            Err(_e) => Err(Error::RequestTimeout),
        }
    }
}
