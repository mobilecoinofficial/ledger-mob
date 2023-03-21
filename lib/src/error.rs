// Copyright (c) 2022-2023 The MobileCoin Foundation

use core::fmt::Debug;
use std::fmt::Display;

use ledger_mob_apdu::state::TxState;
use mc_crypto_ring_signature_signer::Error as SignerError;
use tokio::time::error::Elapsed;

/// Ledger MobileCoin API Error Type
#[derive(Debug, thiserror::Error)]
pub enum Error<E: Display + Debug> {
    /// HID Init Error
    #[error("could not create HidApi instance")]
    HidInit,

    /// Ledger HID Error
    #[error("Transport error {0}")]
    Transport(E),

    /// Invalid transaction state
    #[error("Invalid transaction state (actual: {0}, expected: {1})")]
    InvalidState(TxState, TxState),

    /// Unexpected APDU response
    #[error("Unexpected APDU response")]
    UnexpectedResponse,

    /// Mismatch in rolling transaction digest
    #[error("Mismatch in rolling transaction digest")]
    DigestMismatch,

    /// Error signing ring
    #[error("Ring signing failed: {0}")]
    Ring(SignerError),

    /// Timeout waiting for user
    #[error("Timeout waiting for user interaction")]
    UserTimeout,

    /// Request timeout
    #[error("Timeout waiting for device response")]
    RequestTimeout,

    /// Transaction engine error
    #[error("Engine operation failed: {0}")]
    Engine(u16),

    /// User denied operation
    #[error("Operation rejected by user")]
    UserDenied,

    /// Invalid key in response
    #[error("Invalid key object")]
    InvalidKey,
}

impl<E: Display + Debug> From<Error<E>> for SignerError {
    fn from(value: Error<E>) -> Self {
        match value {
            Error::Ring(r) => r,
            _ => SignerError::Unknown,
        }
    }
}

impl<E: Display + Debug> From<Elapsed> for Error<E> {
    fn from(_: Elapsed) -> Self {
        Error::RequestTimeout
    }
}

#[cfg(feature = "transport_hid")]
impl From<ledger_transport_hid::LedgerHIDError> for Error<anyhow::Error> {
    fn from(e: ledger_transport_hid::LedgerHIDError) -> Self {
        Error::Transport(anyhow::anyhow!("HID: {}", e))
    }
}

#[cfg(feature = "transport_tcp")]
impl From<ledger_transport_tcp::Error> for Error<anyhow::Error> {
    fn from(e: ledger_transport_tcp::Error) -> Self {
        Error::Transport(anyhow::anyhow!("TCP: {}", e))
    }
}
