// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ledger MobileCoin API Library (and CLI)
//!

// async traits not yet safe to use
// see https://github.com/rust-lang/rust/issues/91611
// #![feature(async_fn_in_trait)]

pub use ledger_lib::{
    Device, Exchange, Filters, LedgerHandle, LedgerInfo, LedgerProvider, Transport,
};

/// Re-export `ledger-mob-apdu` for consumers
pub use ledger_mob_apdu::{self as apdu};

mod handle;
pub use handle::DeviceHandle;

mod error;
pub use error::Error;

pub mod tx;

pub mod account;
