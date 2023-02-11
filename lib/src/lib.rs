// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ledger MobileCoin API Library (and CLI)
//!

// async traits not yet safe to use
// see https://github.com/rust-lang/rust/issues/91611
// #![feature(async_fn_in_trait)]

use async_trait::async_trait;
use std::{convert::Infallible, fmt::Debug};

pub use ledger_transport::Exchange;

#[cfg(feature = "transport_hid")]
use hidapi::{HidApi, HidError};

/// Re-export transports for consumer use
pub mod transport {
    #[cfg(feature = "transport_hid")]
    pub use ledger_transport_hid::TransportNativeHID;

    #[cfg(feature = "transport_tcp")]
    pub use ledger_transport_tcp::{TcpOptions, TransportTcp};
}
use transport::*;

/// Re-export `ledger-mob-apdu` for consumers
pub use ledger_mob_apdu::{self as apdu};

mod handle;
pub use handle::DeviceHandle;

mod error;
pub use error::Error;

pub mod tx;
use tx::TransactionHandle;

// Setup global / shared hidapi handle
// TODO: this will cause problems if anyone else has an open hidapi handle
#[cfg(feature = "transport_hid")]
lazy_static::lazy_static! {
    static ref HIDAPI: Result<HidApi, HidError> = hidapi::HidApi::new();
}

/// Ledger provider manages ledger devices and connections
pub struct LedgerProvider {}

impl LedgerProvider {
    /// Create a new ledger provider
    pub fn new() -> Result<Self, Error<Infallible>> {
        // Check we have an HidApi instance
        #[cfg(feature = "transport_hid")]
        let _hid_api = match &*HIDAPI {
            Ok(v) => v,
            Err(_e) => return Err(Error::HidInit),
        };

        Ok(Self {})
    }

    /// List available ledger devices
    #[cfg(feature = "transport_hid")]
    pub fn list_devices(&self) -> impl Iterator<Item = hidapi::DeviceInfo> {
        let hid_api = match &*HIDAPI {
            Ok(v) => v,
            Err(_e) => panic!("Invalid HIDAPI state"),
        };

        // Scan for devices
        let devices: Vec<_> = TransportNativeHID::list_ledgers(hid_api).cloned().collect();

        log::debug!("Found devices: {:?}", devices);

        devices.into_iter()
    }
}

/// Connect trait for supported transports
#[async_trait]
pub trait Connect<T: Exchange> {
    type Options: Debug;

    async fn connect(
        &self,
        opts: &Self::Options,
    ) -> Result<DeviceHandle<T>, Error<<T as Exchange>::Error>>;
}

/// Connect implementation for HID devices
#[cfg(feature = "transport_hid")]
#[async_trait]
impl Connect<TransportNativeHID> for LedgerProvider {
    type Options = hidapi::DeviceInfo;

    async fn connect(
        &self,
        opts: &Self::Options,
    ) -> Result<DeviceHandle<TransportNativeHID>, Error<<TransportNativeHID as Exchange>::Error>>
    {
        let hid_api = match &*HIDAPI {
            Ok(v) => v,
            Err(_e) => return Err(Error::HidInit),
        };

        // Connect to device
        let t = TransportNativeHID::open_device(hid_api, opts).map_err(Error::Transport)?;

        // Create handle
        let d = DeviceHandle::from(t);

        Ok(d)
    }
}

/// Connect implementation for TCP devices
#[cfg(feature = "transport_tcp")]
#[async_trait]
impl Connect<TransportTcp> for LedgerProvider {
    type Options = ledger_transport_tcp::TcpOptions;

    async fn connect(
        &self,
        opts: &Self::Options,
    ) -> Result<DeviceHandle<TransportTcp>, Error<<TransportTcp as Exchange>::Error>> {
        // Connect to device
        let t = TransportTcp::new(opts.clone())
            .await
            .map_err(Error::Transport)?;

        // Create handle
        let d = DeviceHandle::from(t);

        Ok(d)
    }
}
