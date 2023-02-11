// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Handle for connected ledger devices
//!
//! This provides methods for interacting with the device
//! and is generic over [Exchange]

use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::PublicKey;
use futures::executor::block_on;
use log::debug;

use ledger_mob_apdu::{
    ident::{IdentGetReq, IdentResp, IdentSignReq},
    key_image::{KeyImageReq, KeyImageResp},
    state::TxState,
    subaddress_keys::{SubaddressKeyReq, SubaddressKeyResp},
    tx::{TxInfo, TxInfoReq},
    wallet_keys::{WalletKeyReq, WalletKeyResp},
};
use mc_core::account::{ViewAccount, ViewSubaddress};
use mc_transaction_signer::traits::{KeyImageComputer, ViewAccountProvider};

use ledger_apdu::{ApduBase, ApduCmd};
use ledger_transport::Exchange;

use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature::KeyImage;

use crate::{
    tx::{TransactionHandle, TxConfig},
    Error,
};

/// Handle for a connected ledger device.
///
/// This is generic over [Exchange] types to support different
/// underlying transports
#[derive(Clone)]
pub struct DeviceHandle<T: Exchange> {
    t: T,
    user_timeout_s: usize,
    request_timeout_s: usize,
}

/// Create a [DeviceHandle] wrapper from a type implementing [Exchange]
impl<T: Exchange + Sync + Send> From<T> for DeviceHandle<T> {
    fn from(t: T) -> Self {
        Self {
            t,
            user_timeout_s: 10,
            request_timeout_s: 2,
        }
    }
}

impl<T: Exchange + Sync + Send> DeviceHandle<T> {
    /// Fetch root keys for the provided account index
    pub async fn account_keys(
        &self,
        account_index: u32,
    ) -> Result<ViewAccount, Error<<T as Exchange>::Error>> {
        let mut buff = [0u8; 256];

        debug!("Requesting root keys for account: {}", account_index);

        let req = WalletKeyReq::new(account_index);
        let resp = self.exchange::<WalletKeyResp>(req, &mut buff).await?;

        Ok(ViewAccount::new(resp.view_private, resp.spend_public))
    }

    /// Fetch subaddress keys for the provided account and subaddress index
    pub async fn subaddress_keys(
        &self,
        account_index: u32,
        subaddress_index: u64,
    ) -> Result<ViewSubaddress, Error<<T as Exchange>::Error>> {
        let mut buff = [0u8; 256];

        debug!(
            "Requesting subaddress keys for account: {}, subaddress: {}",
            account_index, subaddress_index
        );

        let req = SubaddressKeyReq::new(account_index, subaddress_index);
        let resp = self.exchange::<SubaddressKeyResp>(req, &mut buff).await?;

        Ok(ViewSubaddress {
            view_private: resp.view_private,
            spend_public: resp.spend_public,
        })
    }

    /// Resolve a key image for a given tx_out
    pub async fn key_image(
        &self,
        account_index: u32,
        subaddress_index: u64,
        tx_public_key: RistrettoPublic,
    ) -> Result<KeyImage, Error<<T as Exchange>::Error>> {
        let mut buff = [0u8; 256];

        debug!(
            "Resolving key image for account: {}, subaddress: {}, tx_public_key: {}",
            account_index, subaddress_index, tx_public_key
        );

        let req = KeyImageReq::new(account_index, subaddress_index, tx_public_key.into());
        let resp = self.exchange::<KeyImageResp>(req, &mut buff).await?;

        Ok(resp.key_image)
    }

    /// Fetch a handle to a specific on-device account by SLIP-0010 index
    pub async fn account(&self, account_index: u32) -> AccountHandle<&Self> {
        // TODO: prompt device to generate / cache account keys for re-use

        // Return wrapped handle
        AccountHandle {
            account_index,
            t: self,
        }
    }

    /// Start a transaction
    ///
    /// This returns a stateful [TransactionHandle] that must be used
    /// for further operations.
    /// Note that misuse / reordering will cause the transaction to fail.
    pub async fn transaction(
        &self,
        opts: TxConfig,
    ) -> Result<TransactionHandle<&Self>, Error<<T as Exchange>::Error>> {
        debug!("Starting transaction: {:?}", opts);

        let t = TransactionHandle::init(opts, self).await.unwrap();

        Ok(t)
    }

    /// Execute and identity challenge and response
    pub async fn identity(
        &self,
        index: u32,
        uri: &str,
        challenge: &[u8],
    ) -> Result<(PublicKey, [u8; 64]), Error<<T as Exchange>::Error>> {
        let mut buff = [0u8; 256];

        debug!("Executing identity challenge");

        // Issue signing request
        let req = IdentSignReq::new(index, uri, challenge);
        let resp = self.exchange::<TxInfo>(req, &mut buff).await?;

        if resp.state != TxState::IdentPending {
            return Err(Error::InvalidState(resp.state, TxState::IdentPending));
        }

        // Await user approval
        let n = self.user_timeout_s;
        for i in 0..n {
            let resp = self.exchange::<TxInfo>(TxInfoReq, &mut buff).await?;

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

        let resp = self.exchange::<IdentResp>(IdentGetReq, &mut buff).await?;

        let public_key = PublicKey::from_bytes(&resp.public_key).map_err(|_| Error::InvalidKey)?;

        Ok((public_key, resp.signature))
    }
}

/// Handle to a hardware wallet configured with an account index
///
/// See [DeviceHandle::account][super::DeviceHandle::account] to
/// create a [AccountHandle]
#[derive(Clone)]
pub struct AccountHandle<T: Exchange + Sync + Send> {
    account_index: u32,
    t: T,
}

impl<T: Exchange + Sync + Send> AccountHandle<T> {}

impl<T: Exchange + Sync + Send> KeyImageComputer for AccountHandle<T>
where
    <T as Exchange>::Error: Send + Sync,
{
    type Error = Error<<T as Exchange>::Error>;

    fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &mc_core::keys::TxOutPublic,
    ) -> Result<KeyImage, Self::Error> {
        let mut buff = [0u8; 256];

        tokio::task::block_in_place(|| {
            block_on(async {
                debug!(
                    "Resolving key image for account: {}, subaddress: {}, tx_public_key: {}",
                    self.account_index, subaddress_index, tx_out_public_key
                );

                let req = KeyImageReq::new(
                    self.account_index,
                    subaddress_index,
                    tx_out_public_key.clone(),
                );
                let resp = self
                    .t
                    .exchange::<KeyImageResp>(req, &mut buff)
                    .await
                    .map_err(Error::Transport)?;

                Ok(resp.key_image)
            })
        })
    }
}

impl<T: Exchange + Sync + Send> ViewAccountProvider for AccountHandle<T>
where
    <T as Exchange>::Error: Send + Sync,
{
    type Error = Error<<T as Exchange>::Error>;

    fn account(&self) -> Result<ViewAccount, Self::Error> {
        let mut buff = [0u8; 256];

        tokio::task::block_in_place(|| {
            block_on(async {
                debug!("Requesting root keys for account: {}", self.account_index);

                let req = WalletKeyReq::new(self.account_index);
                let resp = self
                    .t
                    .exchange::<WalletKeyResp>(req, &mut buff)
                    .await
                    .map_err(Error::Transport)?;

                Ok(ViewAccount::new(resp.view_private, resp.spend_public))
            })
        })
    }
}

/// Re-export [Exchange] trait for [DeviceHandle]
#[async_trait]
impl<T: Exchange + Sync + Send> Exchange for DeviceHandle<T> {
    type Error = Error<<T as Exchange>::Error>;

    async fn exchange<'a, 'c, ANS: ApduBase<'a>>(
        &self,
        req: impl ApduCmd<'c>,
        buff: &'a mut [u8],
    ) -> Result<ANS, Self::Error> {
        // Execute exchange with internal timeout
        match tokio::time::timeout(
            Duration::from_secs(self.request_timeout_s as u64),
            self.t.exchange(req, buff),
        )
        .await
        {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(Error::Transport(e)),
            Err(_e) => Err(Error::RequestTimeout),
        }
    }
}
