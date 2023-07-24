// Copyright (c) 2022-2023 The MobileCoin Foundation

//! MobileCoin hardware wallet core
//!
//! This provides a common [Engine][engine] supporting transaction signing and verification
//! for execution on hardware wallets.
//!
//! Interactions with the [Engine][engine] are performed via [Event][engine::Event]s and [Output][engine::Output]s, translated into [APDUs][ledger_mob_apdu] over the wire.
//!
//! ## Operations
//!
//! Prior to interacting with a hardware wallet the client should issue an
//! [`AppInfoReq`][apdu::app_info::AppInfoReq] to fetch an
//! [`AppInfoResp`][apdu::app_info::AppInfoResp] containing application information
//! including the applet version, protocol version, and flags for available features.
//!
//! ### Requesting wallet / subaddress keys
//!
//! Wallet keys can be requested via [`WalletKeyReq`][apdu::wallet_keys::WalletKeyReq]
//! APDU, returning a [`WalletKeyResp`][apdu::wallet_keys::WalletKeyResp] containing
//! the root spend public key and view private key for a given account index.
//!
//! SubAddress keys can be requested via [`WalletKeyReq`][apdu::subaddress_keys::SubaddressKeyReq]
//! APDU, returning a [`WalletKeyResp`][apdu::subaddress_keys::SubaddressKeyResp] containing
//! the subaddress spend public key and view private key for a given account index.
//!
//! ### Key Image Scanning
//!
//! Key images can be recovered via [`KeyImageReq`][apdu::key_image::KeyImageReq] request,
//! returning a [`KeyImageResp`][apdu::key_image::KeyImageResp] APDU containing the computed
//! key image.
//!
//!
//! ### Executing a transaction
//!
//! Transactions consist of a series of operations to first configure the
//! transaction, sign memos for the transaction, then to sign the set of
//! rings included in the transaction.
//!
//! Unless otherwise documented each transaction operation returns a
//! [`TxInfo`][apdu::tx::TxInfo] response containing the current
//! [transaction state][apdu::tx::TxState] as well as a
//! [`TxDigest`][engine::TxDigest] computed from the inputs to the transaction.
//! This digest ensures the executed transaction matches the callers expectations,
//! and _MUST_ be cached on [`TxInit`][apdu::tx::TxInit] and updated and
//! compared for each operation during a transaction, with the transaction
//! discarded if a mismatch is detected.
//!
//!
//! 1. Issue [`TxInit`][apdu::tx::TxInit] with transaction options to start a transaction operation
//! 2. Generate and sign memos
//!     1. Issue [`TxMemoSign`][apdu::tx::TxMemoSign] to fetch a [`TxMemoSig`][apdu::tx::TxMemoSig]
//!        APDU containing a signature for the provided memo
//! 3. Set transaction message via [`TxSetMessage`][apdu::tx::TxSetMessage] APDU (see notes)
//! 4. Sign N rings
//!     1. Issue [`TxRingInit`][apdu::tx::TxRingInit] to start a ring signing operation
//!     2. Issue [`TxSetBlinding`][apdu::tx::TxSetBlinding] to set the blinding values for the ring
//!     3. Issue [`TxAddTxOut`][apdu::tx::TxAddTxOut] for each ring entry
//!        (in order of `real_index` to `(real_index - 1) % ring_size)`
//!     4. Issue [`TxRingSign`][apdu::tx::TxRingSign] to complete signing
//!     5. Issue [`TxGetKeyImage`][apdu::tx::TxGetKeyImage] to fetch a [`TxKeyImage`][apdu::tx::TxKeyImage]
//!        APDU containing the key image and zeroth challenge for the signed ring
//!     6. Issue [`TxGetResponse`][apdu::tx::TxGetResponse] to fetch [`TxResponse`][apdu::tx::TxResponse]
//!        APDU the response scalar for each ring entry
//! 5. Issue [`TxComplete`][apdu::tx::TxComplete] to complete transaction
//!
//!
//!
//! ### Notes
//!
//! - `TxSetMessage` to be replaced with streaming of tx summaries to support computation
//! of the tx prefix on device and allow the device to verify transaction values once
//! [MCIP#52](https://github.com/mobilecoinfoundation/mcips/pull/52)
//! ([mobilecoin#2683](https://github.com/mobilecoinfoundation/mobilecoin/pull/2683)) is available.
//!

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use ledger_mob_apdu::{self as apdu};

pub mod engine;

pub mod helpers;

pub use mc_transaction_types::TokenId;
