// Copyright (c) 2022-2023 The MobileCoin Foundation

use core::fmt::Debug;

use ledger_mob_apdu::state::TxState;
use mc_crypto_ring_signature_signer::Error as SignerError;
use tokio::time::error::Elapsed;

/// Ledger MobileCoin API Error Type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No device found
    #[error("no device found")]
    NoDevice,

    /// HID Init Error
    #[error("could not create HidApi instance")]
    HidInit,

    /// Ledger HID Error
    #[cfg(feature = "transport_hid")]
    #[error("Transport error {0}")]
    Hid(#[from] hidapi::HidError),

    /// Ledger IO Error
    #[error("IO error {0}")]
    Io(#[from] std::io::Error),

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

    /// Invalid length
    #[error("Invalid length")]
    InvalidLength,

    /// UTF8 encoding error
    #[error("UTF8 encoding error")]
    Utf8,

    /// APDU error
    #[error("APDU error")]
    Apdu(#[from] ledger_apdu::ApduError),

    /// Ring CT error
    #[error("Ring CT error: {0}")]
    RingCt(mc_transaction_core::ring_ct::Error),

    /// Ring signer error
    #[error("Ring signer error: {0}")]
    RingSigner(mc_crypto_ring_signature::Error),

    /// Unknown (TEMPORARY)
    /// TODO: remove once ledger_transport_tcp is updated / fixed
    #[error("Unknown error")]
    Unknown,
}

impl From<Error> for SignerError {
    fn from(value: Error) -> Self {
        match value {
            Error::Ring(r) => r,
            _ => SignerError::Unknown,
        }
    }
}

impl From<Elapsed> for Error {
    fn from(_: Elapsed) -> Self {
        Error::RequestTimeout
    }
}

impl From<mc_crypto_ring_signature::Error> for Error {
    fn from(value: mc_crypto_ring_signature::Error) -> Self {
        Error::RingSigner(value)
    }
}

impl From<mc_transaction_core::ring_ct::Error> for Error {
    fn from(value: mc_transaction_core::ring_ct::Error) -> Self {
        Error::RingCt(value)
    }
}
