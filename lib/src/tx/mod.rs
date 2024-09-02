// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Transaction APIs
//!
//!

use async_trait::async_trait;
use log::debug;
use std::{cell::RefCell, sync::Arc, time::Duration};
use tokio::sync::Mutex;

use ledger_lib::Device;
use ledger_proto::{ApduBase, ApduReq};

use ledger_mob_apdu::{
    state::{Digest, TxState},
    tx::{TxComplete, TxInfo, TxInfoReq, TxInit, TxSetMessage},
};

use crate::Error;

mod key_image;
mod memo;
mod ring;
mod subaddress;
mod summary;

/// Configuration for a transaction operation
#[derive(Clone, Debug, PartialEq)]
pub struct TxConfig {
    /// Account index for key derivation
    pub account_index: u32,

    /// Number of memos
    pub num_memos: usize,

    /// Number of rings
    pub num_rings: usize,

    /// APDU request timeout
    pub request_timeout: Duration,

    /// User interaction timeout
    pub user_timeout: Duration,
}

/// Handle to a hardware wallet configured for transaction execution
///
/// See [DeviceHandle::transaction][super::DeviceHandle::transaction] to
/// create a [TransactionHandle]
pub struct TransactionHandle<T: Device> {
    /// Device for communication
    t: Arc<Mutex<T>>,

    /// General transaction configuration
    info: TxConfig,

    /// Transaction state information
    state: RefCell<TransactionState>,
}

struct TransactionState {
    /// Digest computed over transaction inputs
    digest: Digest,

    /// Number of memos
    memo_count: usize,

    /// Number of rings
    ring_count: usize,
}

impl<T: Device + Send> TransactionHandle<T> {
    /// Initialise a new transaction over the provided device
    pub async fn new(info: TxConfig, transport: Arc<Mutex<T>>) -> Result<Self, Error> {
        let mut buff = [0u8; 256];

        // Setup transaction
        let tx_init = TxInit::new(info.account_index, info.num_rings as u8);
        let mut t = transport.lock().await;

        let r = t
            .request::<TxInfo>(tx_init, &mut buff, info.request_timeout)
            .await?;
        drop(t);

        // TODO: Check the device has entered the Init state
        //Self::check_state(r.state, TxState::Init)?;

        // Return transaction handle
        Ok(Self {
            info,
            t: transport,
            state: RefCell::new(TransactionState {
                digest: r.digest,
                memo_count: 0,
                ring_count: 0,
            }),
        })
    }

    /// Set message for transaction
    pub async fn set_message(&mut self, m: &[u8]) -> Result<(), Error> {
        let mut buff = [0u8; 256];

        // Build request
        let req = TxSetMessage::new(m);

        // Update transaction digest

        let digest = {
            let mut state = self.state.borrow_mut();
            Digest::update(&mut state.digest, &req.hash()).clone()
        };
        let mut t = self.t.lock().await;

        // Issue request
        let resp = t
            .request::<TxInfo>(req, &mut buff, self.info.request_timeout)
            .await?;

        // Check state and expected digest
        check_state(resp.state, TxState::Pending)?;
        check_digest(&resp.digest, &digest)?;

        Ok(())
    }

    /// Await on-device transaction approval
    pub async fn await_approval(&mut self, timeout_s: u32) -> Result<(), Error> {
        let mut buff = [0u8; 256];

        for _i in 0..timeout_s {
            // Issue TxInfo request
            let r = self
                .request::<TxInfo>(TxInfoReq {}, &mut buff, self.info.request_timeout)
                .await;

            debug!("awaiting tx approval (state: {:?})", r);

            // Handle responses, waiting for `Ready`, `Denied` or `Error` states
            match r {
                Ok(v) if v.state == TxState::Pending => (),
                Ok(v) if v.state == TxState::Ready => return Ok(()),
                Ok(v) if v.state == TxState::TxDenied => return Err(Error::UserDenied),
                Ok(v) if v.state == TxState::Error => return Err(Error::Engine(0)),
                Ok(v) => return Err(Error::InvalidState(v.state, TxState::Pending)),
                Err(_) => (),
            }

            // Sleep while we wait
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Err(Error::UserTimeout)
    }

    /// Signal transaction completion
    pub async fn complete(mut self) -> Result<(), Error> {
        let mut buff = [0u8; 256];

        let _r = self
            .request::<TxInfo>(TxComplete, &mut buff, self.info.request_timeout)
            .await?;

        Ok(())
    }
}

/// Helper to check state when executing transactions
pub(crate) fn check_state(actual: TxState, expected: TxState) -> Result<(), Error> {
    if actual != expected {
        Err(Error::InvalidState(actual, expected))
    } else {
        Ok(())
    }
}

/// Helper to check digest when executing transactions
pub(crate) fn check_digest(actual: &Digest, expected: &Digest) -> Result<(), Error> {
    if expected != actual {
        Err(Error::DigestMismatch)
    } else {
        Ok(())
    }
}

/// Exchange impl on transaction context
#[async_trait]
impl<T: Device + Send> Device for TransactionHandle<T> {
    /// Helper for executing transactions with the device
    async fn request<'a, 'b, RESP: ApduBase<'b>>(
        &mut self,
        request: impl ApduReq<'a> + Send,
        buff: &'b mut [u8],
        timeout: Duration,
    ) -> Result<RESP, ledger_lib::Error> {
        self.t.lock().await.request(request, buff, timeout).await
    }
}
