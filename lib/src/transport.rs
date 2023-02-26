//! Generic transport abstraction for hiding underlying transport types
//!
// Copyright (c) 2022-2023 The MobileCoin Foundation

use async_trait::async_trait;
use ledger_apdu::{ApduBase, ApduCmd};
use ledger_transport::Exchange;

#[cfg(feature = "transport_hid")]
pub use ledger_transport_hid::TransportNativeHID;

#[cfg(feature = "transport_tcp")]
pub use ledger_transport_tcp::{TcpOptions, TransportTcp};

use crate::Error;

/// Re-export HID transport error type
#[cfg(feature = "transport_hid")]
pub type TransportHidError = Error<ledger_transport_hid::LedgerHIDError>;

/// Re-export TCP transport error type
#[cfg(feature = "transport_tcp")]
pub type TransportTcpError = Error<ledger_transport_tcp::Error>;

/// Generic ledger device (abstract over transport types)
pub enum GenericTransport {
    #[cfg(feature = "transport_hid")]
    Hid(TransportNativeHID),
    #[cfg(feature = "transport_tcp")]
    Tcp(TransportTcp),
}

/// Generic transport error
#[derive(Debug, thiserror::Error)]
pub enum GenericError {
    #[cfg(feature = "transport_hid")]
    #[error("HID transport error: {0}")]
    Hid(#[from] ledger_transport_hid::LedgerHIDError),

    #[cfg(feature = "transport_tcp")]
    #[error("TCP transport error: {0}")]
    Tcp(#[from] ledger_transport_tcp::Error),
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
    type Error = GenericError;

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
        };

        Ok(r)
    }
}

#[cfg(feature = "transport_hid")]
impl From<ledger_transport_hid::LedgerHIDError> for Error<GenericError> {
    fn from(e: ledger_transport_hid::LedgerHIDError) -> Self {
        Error::Transport(e.into())
    }
}

#[cfg(feature = "transport_tcp")]
impl From<ledger_transport_tcp::Error> for Error<GenericError> {
    fn from(e: ledger_transport_tcp::Error) -> Self {
        Error::Transport(e.into())
    }
}
