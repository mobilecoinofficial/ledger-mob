// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ledger MobileCoin API Library (and CLI)
//!

// async traits not yet safe to use
// see https://github.com/rust-lang/rust/issues/91611
// #![feature(async_fn_in_trait)]

use async_trait::async_trait;
use std::{convert::Infallible, fmt::Debug};
use transport::GenericError;

pub use ledger_transport::Exchange;

#[cfg(feature = "transport_hid")]
use hidapi::{HidApi, HidError};

/// Re-export transports for consumer use
pub mod transport;
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

/// Device discovery filter
#[derive(Clone, Debug, PartialEq, clap::ValueEnum, strum::Display)]
#[non_exhaustive]
pub enum Filter {
    /// List all devices available using supported transport
    Any,
    /// List only HID devices
    Hid,
    /// List only TCP devices
    Tcp,
}

/// Ledger device information for listing, used by connect
#[derive(Debug)]
pub enum LedgerInfo {
    #[cfg(feature = "transport_hid")]
    Hid(hidapi::DeviceInfo),
    #[cfg(feature = "transport_tcp")]
    Tcp(TcpOptions),
}

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
    pub async fn list_devices(&self, filter: Filter) -> Vec<LedgerInfo> {
        let mut devices = vec![];

        #[cfg(feature = "transport_hid")]
        if filter == Filter::Any || filter == Filter::Hid {
            let hid_api = match &*HIDAPI {
                Ok(v) => v,
                Err(_e) => panic!("Invalid HIDAPI state"),
            };

            TransportNativeHID::list_ledgers(hid_api)
                .cloned()
                .for_each(|d| {
                    devices.push(LedgerInfo::Hid(d));
                });
        }

        #[cfg(feature = "transport_tcp")]
        if filter == Filter::Any || filter == Filter::Tcp {
            // Try connecting to default speculos port
            let o = TcpOptions::default();
            if let Ok(_t) =
                tokio::net::TcpStream::connect(std::net::SocketAddr::new(o.addr, o.port)).await
            {
                // Return default port if connection succeeded
                devices.push(LedgerInfo::Tcp(o));
            };
        }

        log::debug!("Found {} devices: {:?}", devices.len(), devices);

        devices
    }
}

/// Generic ledger device handle (abstract over transport types)
pub type GenericHandle = DeviceHandle<GenericTransport>;

impl GenericHandle {
    /// Create a new generic device handle
    pub fn new(d: impl Into<GenericTransport>) -> Self {
        Self::from(d.into())
    }
}

impl std::fmt::Display for LedgerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "transport_hid")]
            LedgerInfo::Hid(hid_info) => {
                write!(
                    f,
                    "{:16} (USB, {:04x}:{:04x}, {})",
                    hid_info.product_string().unwrap_or("UNKNOWN"),
                    hid_info.vendor_id(),
                    hid_info.product_id(),
                    hid_info.serial_number().unwrap_or("UNKNOWN"),
                )
            }
            #[cfg(feature = "transport_tcp")]
            LedgerInfo::Tcp(tcp_info) => {
                write!(
                    f,
                    "{:16} (TCP, {}:{})",
                    "Speculos", tcp_info.addr, tcp_info.port
                )
            }
            #[cfg(not(all(feature = "transport_hid", feature = "transport_tcp")))]
            _ => panic!("Transport {} unavailable", self),
        }
    }
}

/// Connect trait for supported transports
#[async_trait]
pub trait Connect<T: Exchange> {
    type Options: Debug;

    /// Connect to the specified device
    async fn connect(
        &self,
        opts: &Self::Options,
    ) -> Result<DeviceHandle<T>, Error<<T as Exchange>::Error>>;
}

/// Generic connect implementation
#[cfg(any(feature = "transport_hid", feature = "transport_tcp"))]
#[async_trait]
impl Connect<GenericTransport> for LedgerProvider {
    type Options = LedgerInfo;

    async fn connect(
        &self,
        opts: &Self::Options,
    ) -> Result<DeviceHandle<GenericTransport>, Error<GenericError>> {
        let t = match opts {
            #[cfg(feature = "transport_hid")]
            LedgerInfo::Hid(hid_info) => {
                let hid_api = match &*HIDAPI {
                    Ok(v) => v,
                    Err(_e) => return Err(Error::HidInit),
                };

                // Connect to device
                let t = TransportNativeHID::open_device(hid_api, hid_info)?;

                // Create handle
                GenericTransport::Hid(t)
            }
            #[cfg(feature = "transport_tcp")]
            LedgerInfo::Tcp(tcp_info) => {
                // Connect to device
                let t = TransportTcp::new(tcp_info.clone()).await?;

                GenericTransport::Tcp(t)
            }
        };

        Ok(DeviceHandle::from(t))
    }
}

/// Connect implementation for HID devices
#[cfg(feature = "transport_hid")]
#[async_trait]
impl Connect<TransportNativeHID> for LedgerProvider {
    type Options = hidapi::DeviceInfo;

    async fn connect(
        &self,
        opts: &Self::Options,
    ) -> Result<DeviceHandle<TransportNativeHID>, TransportHidError> {
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
    ) -> Result<DeviceHandle<TransportTcp>, TransportTcpError> {
        // Connect to device
        let t = TransportTcp::new(opts.clone())
            .await
            .map_err(Error::Transport)?;

        // Create handle
        let d = DeviceHandle::from(t);

        Ok(d)
    }
}
