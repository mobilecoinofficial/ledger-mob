//! Generic transport abstraction for hiding underlying transport types
//!
// Copyright (c) 2022-2023 The MobileCoin Foundation

use async_trait::async_trait;
use ledger_apdu::{ApduBase, ApduCmd};
use ledger_transport::Exchange;

#[cfg(feature = "transport_hid")]
pub use ledger_transport_hid::{LedgerHIDError, TransportNativeHID};

#[cfg(feature = "transport_tcp")]
pub use ledger_transport_tcp::{Error as LedgerTcpError, TcpOptions, TransportTcp};
use strum::Display;

use crate::Error;

/// Generic ledger device (abstract over transport types)
#[derive(Display)]
#[non_exhaustive]
pub enum GenericTransport {
    #[cfg(feature = "transport_hid")]
    Hid(TransportNativeHID),
    #[cfg(feature = "transport_tcp")]
    Tcp(TransportTcp),
}

/// Convert a HID transport into a generic transport
#[cfg(feature = "transport_hid")]
impl From<TransportNativeHID> for GenericTransport {
    fn from(t: TransportNativeHID) -> Self {
        Self::Hid(t)
    }
}

/// Convert a TCP transport into a generic transport
#[cfg(feature = "transport_tcp")]
impl From<ledger_transport_tcp::TransportTcp> for GenericTransport {
    fn from(t: TransportTcp) -> Self {
        Self::Tcp(t)
    }
}

/// Implementation of [Exchange] for [GenericDevice], hiding transport error types
#[async_trait]
impl Exchange for GenericTransport {
    type Error = Error;

    async fn exchange<'a, 'c, ANS: ApduBase<'a>>(
        &self,
        req: impl ApduCmd<'c>,
        buff: &'a mut [u8],
    ) -> Result<ANS, Self::Error> {
        let r = match self {
            #[cfg(feature = "transport_hid")]
            Self::Hid(t) => t.exchange(req, buff).await?,
            #[cfg(feature = "transport_tcp")]
            Self::Tcp(t) => t.exchange(req, buff).await?,
            #[cfg(not(all(feature = "transport_hid", feature = "transport_tcp")))]
            _ => panic!("Transport {} unavailable", self),
        };

        Ok(r)
    }
}

#[cfg(feature = "transport_hid")]
impl From<LedgerHIDError> for Error {
    fn from(e: LedgerHIDError) -> Self {
        match e {
            LedgerHIDError::DeviceNotFound => Error::NoDevice,
            LedgerHIDError::Comm(_e) => Error::Unknown,
            LedgerHIDError::Hid(e) => Error::Hid(e),
            LedgerHIDError::Io(e) => Error::Io(e),
            LedgerHIDError::UTF8(_e) => Error::Utf8,
            LedgerHIDError::Apdu(e) => Error::Apdu(e),
        }
    }
}

#[cfg(feature = "transport_tcp")]
impl From<LedgerTcpError> for Error {
    fn from(e: LedgerTcpError) -> Self {
        match e {
            LedgerTcpError::Io(e) => Error::Io(e),
            LedgerTcpError::Timeout => Error::RequestTimeout,
            LedgerTcpError::InvalidLength => Error::InvalidLength,
            LedgerTcpError::InvalidAnswer => Error::UnexpectedResponse,
            LedgerTcpError::ApduError => Error::Unknown,
        }
    }
}
