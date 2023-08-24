// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Handle for connected ledger devices
//!
//! This provides methods for interacting with the device
//! and is generic over [ledger_lib::Device]

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use ledger_lib::Device;
use ledger_proto::{ApduBase, ApduReq};
use log::debug;
use rand_core::OsRng;
use tokio::sync::Mutex;

use ledger_mob_apdu::{
    app_info::AppFlags,
    ident::{IdentGetReq, IdentResp, IdentSignReq},
    key_image::{KeyImageReq, KeyImageResp},
    prelude::{AppInfoReq, AppInfoResp},
    state::TxState,
    subaddress_keys::{SubaddressKeyReq, SubaddressKeyResp},
    tx::{TxInfo, TxInfoReq},
    wallet_keys::{WalletKeyReq, WalletKeyResp},
};

use mc_core::{
    account::{ViewAccount, ViewSubaddress},
    keys::TxOutPublic,
};
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature::KeyImage;
use mc_transaction_core::{ring_ct::InputRing, tx::Tx};
use mc_transaction_extra::UnsignedTx;
use mc_transaction_signer::types::TxoSynced;

use crate::{
    account::AccountHandle,
    tx::{TransactionHandle, TxConfig},
    Error,
};

/// MobileCoin handle for a connected ledger [Device].
///
/// This is generic over [Device] types to support different
/// underlying transports / providers
#[derive(Clone)]
pub struct DeviceHandle<T: Device> {
    /// Device handle for communication
    t: Arc<Mutex<T>>,
    /// Timeout for user acknowledgements
    user_timeout_s: usize,
    /// Timeout for APDU requests
    request_timeout_s: usize,
}

/// Create a [DeviceHandle] wrapper from a type implementing [Device]
impl<T: Device> From<T> for DeviceHandle<T> {
    fn from(t: T) -> Self {
        Self {
            t: Arc::new(Mutex::new(t)),
            user_timeout_s: 10,
            request_timeout_s: 2,
        }
    }
}

unsafe impl<T: Device> Send for DeviceHandle<T> {}

#[derive(Clone, Debug, PartialEq)]
pub struct MobAppInfo {
    pub app_name: String,
    pub app_version: String,
    pub protocol_version: u8,
    pub flags: AppFlags,
}

impl<T: Device + Send> DeviceHandle<T> {
    /// Helper to fetch user interaction timeout
    fn user_timeout(&self) -> Duration {
        Duration::from_secs(self.user_timeout_s as u64)
    }

    /// Helper to fetch APDU request timeout
    fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_s as u64)
    }

    /// Fetch ledger application info
    pub async fn app_info(&mut self) -> Result<MobAppInfo, Error> {
        let mut buff = [0u8; 256];

        debug!("Requesting app info");

        let resp = self
            .request::<AppInfoResp>(AppInfoReq {}, &mut buff, self.request_timeout())
            .await?;

        Ok(MobAppInfo {
            app_name: resp.name.to_string(),
            app_version: resp.version.to_string(),
            protocol_version: resp.proto,
            flags: resp.flags,
        })
    }

    /// Fetch root keys for the provided account index
    pub async fn account_keys(&mut self, account_index: u32) -> Result<ViewAccount, Error> {
        let (mut buff_a, mut buff_b) = ([0u8; 256], [0u8; 256]);

        debug!("Requesting root keys for account: {}", account_index);

        let req = WalletKeyReq::new(account_index);
        let resp = self
            .retry::<WalletKeyResp>(req, &mut buff_a, &mut buff_b)
            .await?;

        Ok(ViewAccount::new(resp.view_private, resp.spend_public))
    }

    /// Fetch subaddress keys for the provided account and subaddress index
    pub async fn subaddress_keys(
        &mut self,
        account_index: u32,
        subaddress_index: u64,
    ) -> Result<ViewSubaddress, Error> {
        let (mut buff_a, mut buff_b) = ([0u8; 256], [0u8; 256]);

        debug!(
            "Requesting subaddress keys for account: {}, subaddress: {}",
            account_index, subaddress_index
        );

        let req = SubaddressKeyReq::new(account_index, subaddress_index);
        let resp = self
            .retry::<SubaddressKeyResp>(req, &mut buff_a, &mut buff_b)
            .await?;

        Ok(ViewSubaddress {
            view_private: resp.view_private,
            spend_public: resp.spend_public,
        })
    }

    /// Resolve a key image for a given tx_out
    pub async fn key_image(
        &mut self,
        account_index: u32,
        subaddress_index: u64,
        tx_public_key: RistrettoPublic,
    ) -> Result<KeyImage, Error> {
        let (mut buff_a, mut buff_b) = ([0u8; 256], [0u8; 256]);

        debug!(
            "Resolving key image for account: {}, subaddress: {}, tx_public_key: {}",
            account_index, subaddress_index, tx_public_key
        );

        let req = KeyImageReq::new(account_index, subaddress_index, tx_public_key.into());
        let resp = self
            .retry::<KeyImageResp>(req, &mut buff_a, &mut buff_b)
            .await?;

        Ok(resp.key_image)
    }

    /// Helper to retry for requests requiring user approval
    // TODO: fix apdu lifetimes so we don't need multiple buffers here / can return immediate errors
    async fn retry<'a, ANS: ApduBase<'a>>(
        &mut self,
        req: impl ApduReq<'_> + Clone + Send,
        buff_a: &'a mut [u8],
        buff_b: &'a mut [u8],
    ) -> Result<ANS, Error> {
        // First request, may succeed or require approval
        if let Ok(v) = self
            .request::<ANS>(req.clone(), buff_a, self.request_timeout())
            .await
        {
            return Ok(v);
        };

        // Poll on app unlock state
        for i in 0..self.user_timeout_s {
            let info = self.app_info().await?;
            match info.flags.contains(AppFlags::UNLOCKED) {
                true => break,
                false if i == self.user_timeout_s - 1 => return Err(Error::UserTimeout),
                false => {
                    debug!("Waiting for user approval: {}s", i);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }

        // Re-issue request
        let resp = self
            .request::<ANS>(req.clone(), buff_b, self.request_timeout())
            .await?;

        Ok(resp)
    }

    /// Fetch a handle to a specific on-device account by SLIP-0010 index
    pub async fn account(&mut self, account_index: u32) -> AccountHandle<T> {
        // TODO: prompt device to generate / cache account keys for re-use

        // Return wrapped handle
        AccountHandle {
            account_index,
            user_timeout: self.user_timeout(),
            t: self.t.clone(),
        }
    }

    /// Sign an unsigned transaction object using the device
    pub async fn transaction(
        &mut self,
        account_index: u32,
        approval_timeout_s: u32,
        unsigned: UnsignedTx,
    ) -> Result<(Tx, Vec<TxoSynced>), Error> {
        // Start device transaction
        debug!("Starting transaction");
        let mut signer = TransactionHandle::new(
            TxConfig {
                account_index,
                num_memos: 0,
                num_rings: unsigned.rings.len(),
                request_timeout: self.request_timeout(),
                user_timeout: Duration::from_secs(approval_timeout_s as u64),
            },
            self.t.clone(),
        )
        .await?;

        // TODO: sign memos (this requires a restructure of UnsignedTx)

        // Build the digest for ring signing
        debug!("Building TX digest");
        let (signing_data, summary, unblinding, digest) =
            unsigned.get_signing_data(&mut OsRng {}).unwrap();

        debug!(
            "Using extended digest: {:02x?}",
            signing_data.mlsag_signing_digest
        );

        // Load transaction summary
        debug!("Loading tx summary");
        signer
            .set_tx_summary(unsigned.block_version, &digest.0, &summary, &unblinding)
            .await?;

        // Await transaction approval
        signer.await_approval(approval_timeout_s).await?;

        // Sign rings
        debug!("Executing signing operation");
        let signature = signing_data.sign(&unsigned.rings, &signer, &mut OsRng {})?;

        debug!("Signing complete");

        // Signal completion to app
        signer.complete().await?;

        // Map key images to real inputs via public key
        let mut txos = vec![];
        for (i, r) in unsigned.rings.iter().enumerate() {
            let tx_out_public_key = match r {
                InputRing::Signable(r) => r.members[r.real_input_index].public_key,
                InputRing::Presigned(_) => panic!("Pre-signed rings unsupported"),
            };

            txos.push(TxoSynced {
                tx_out_public_key: TxOutPublic::from(
                    RistrettoPublic::try_from(&tx_out_public_key).unwrap(),
                ),
                key_image: signature.ring_signatures[i].key_image,
            });
        }

        // Buld transaction object
        let tx = Tx {
            prefix: unsigned.tx_prefix.clone(),
            signature,
            // TODO: where should this come from?
            fee_map_digest: vec![],
        };

        Ok((tx, txos))
    }

    /// Execute and identity challenge and response
    pub async fn identity(
        &mut self,
        index: u32,
        uri: &str,
        challenge: &[u8],
    ) -> Result<(VerifyingKey, [u8; 64]), Error> {
        let mut buff = [0u8; 256];

        debug!("Executing identity challenge");

        // Issue signing request
        let req = IdentSignReq::new(index, uri, challenge);
        let resp = self
            .request::<TxInfo>(req, &mut buff, self.user_timeout())
            .await?;

        if resp.state != TxState::IdentPending {
            return Err(Error::InvalidState(resp.state, TxState::IdentPending));
        }

        // Await user approval
        let n = self.user_timeout_s;
        for i in 0..n {
            let resp = self
                .request::<TxInfo>(TxInfoReq, &mut buff, self.user_timeout())
                .await?;

            match resp.state {
                TxState::IdentApproved => break,
                TxState::IdentPending if i + 1 < n => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                TxState::IdentPending => return Err(Error::UserTimeout),
                _ => return Err(Error::UserDenied),
            }
        }

        // Fetch identity response
        let resp = self
            .request::<IdentResp>(IdentGetReq, &mut buff, self.user_timeout())
            .await?;

        let public_key =
            VerifyingKey::from_bytes(&resp.public_key).map_err(|_| Error::InvalidKey)?;

        Ok((public_key, resp.signature))
    }
}

/// Re-export [Device] trait for MobileCoin [DeviceHandle]
#[async_trait]
impl<T: Device + Send> Device for DeviceHandle<T> {
    async fn request<'a, 'b, RESP: ApduBase<'b>>(
        &mut self,
        request: impl ApduReq<'a> + Send,
        buff: &'b mut [u8],
        timeout: Duration,
    ) -> Result<RESP, ledger_lib::Error> {
        self.t.lock().await.request(request, buff, timeout).await
    }
}
