// Copyright (c) 2022-2023 The MobileCoin Foundation

//! MobileCoin hardware wallet core
//!
//! This provides a common [Engine][engine] supporting transaction signing and verification
//! for execution on hardware wallets.
//!
//! Interactions with the [Engine][engine] are performed via [Event][engine::Event]s and [Output][engine::Output]s,
//! see [ledger_mob_apdu] for APDU objects and wire encodings.
//!
//! ## Operations
//!
//! Prior to interacting with a hardware wallet the client should issue an
//! [`AppInfoReq`][ledger_mob_apdu::app_info::AppInfoReq] to fetch an
//! [`AppInfoResp`][ledger_mob_apdu::app_info::AppInfoResp] containing application information
//! including the applet version, protocol version, and flags for available features.
//!
//! ### Requesting wallet / subaddress keys
//!
//! Wallet keys can be requested via [`WalletKeyReq`][ledger_mob_apdu::wallet_keys::WalletKeyReq]
//! APDU, returning a [`WalletKeyResp`][ledger_mob_apdu::wallet_keys::WalletKeyResp] containing
//! the root spend public key and view private key for a given account index.
//!
//! SubAddress keys can be requested via [`WalletKeyReq`][ledger_mob_apdu::subaddress_keys::SubaddressKeyReq]
//! APDU, returning a [`WalletKeyResp`][ledger_mob_apdu::subaddress_keys::SubaddressKeyResp] containing
//! the subaddress spend public key and view private key for a given account index.
//!
//! ### Key Image Scanning
//!
//! Key images can be recovered via [`KeyImageReq`][ledger_mob_apdu::key_image::KeyImageReq] request,
//! returning a [`KeyImageResp`][ledger_mob_apdu::key_image::KeyImageResp] APDU containing the computed
//! key image.
//!
//!
//! ### Executing a transaction
//!
//! Transactions consist of a series of operations to first configure the
//! transaction, sign memos for the transaction, then to sign the set of
//! rings included in the transaction.
//!
//! See [`lib/src/handle.rs`](https://github.com/mobilecoinofficial/ledger-mob/blob/main/lib/src/handle.rs#L219)
//! for a complete / reference implementation.
//!
//! Unless otherwise documented each transaction operation returns a
//! [`TxInfo`][ledger_mob_apdu::tx::TxInfo] response containing the current
//! [transaction state][ledger_mob_apdu::state::TxState] as well as a
//! [`TxDigest`][engine::TxDigest] computed from the inputs to the transaction.
//! This digest ensures the executed transaction matches the callers expectations,
//! and _MUST_ be cached on [`TxInit`][ledger_mob_apdu::tx::TxInit] and updated and
//! compared for each operation during a transaction, with the transaction
//! discarded if a mismatch is detected.
//!
//!
//! 1. Issue [`TxInit`][ledger_mob_apdu::tx::TxInit] with transaction options to start a transaction operation
//! 2. Generate and sign memos
//!     1. Issue [`TxMemoSign`][ledger_mob_apdu::tx::TxMemoSign] to fetch a [`TxMemoSig`][ledger_mob_apdu::tx::TxMemoSig]
//!        APDU containing a signature for the provided memo
//! 3. Build transaction summary to generate message for signing (see: [MCIP#52](https://github.com/mobilecoinfoundation/mcips/pull/52))
//!     1. Issue [`TxSummaryInit`][ledger_mob_apdu::tx::TxSummaryInit] to start summary generation
//!     2. Add N outputs and unblinding information using [`TxSummaryAddTxOut`][ledger_mob_apdu::tx::TxSummaryAddTxOut] followed by [`TxSummaryAddTxOutUnblinding`][ledger_mob_apdu::tx::TxSummaryAddTxOutUnblinding]
//!     3. Add M inputs via [`TxSummaryAddTxIn`][ledger_mob_apdu::tx::TxSummaryAddTxIn]
//!     4. Issue [`TxSummaryBuild`][ledger_mob_apdu::tx::TxSummaryBuild] to build summary message
//! 4. Sign N rings
//!     1. Issue [`TxRingInit`][ledger_mob_apdu::tx::TxRingInit] to start a ring signing operation
//!     2. Issue [`TxSetBlinding`][ledger_mob_apdu::tx::TxSetBlinding] to set the blinding values for the ring
//!     3. Issue [`TxAddTxOut`][ledger_mob_apdu::tx::TxAddTxOut] for each ring entry
//!        (in order of `real_index` to `(real_index - 1) % ring_size)`
//!     4. Issue [`TxRingSign`][ledger_mob_apdu::tx::TxRingSign] to complete signing
//!     5. Issue [`TxGetKeyImage`][ledger_mob_apdu::tx::TxGetKeyImage] to fetch a [`TxKeyImage`][ledger_mob_apdu::tx::TxKeyImage]
//!        APDU containing the key image and zeroth challenge for the signed ring
//!     6. Issue [`TxGetResponse`][ledger_mob_apdu::tx::TxGetResponse] to fetch [`TxResponse`][ledger_mob_apdu::tx::TxResponse]
//!        APDU containing the response scalar for each ring entry
//! 5. Issue [`TxComplete`][ledger_mob_apdu::tx::TxComplete] to complete transaction
//!
//!

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use ledger_mob_apdu::{self as apdu};

pub mod engine;

pub mod helpers;

pub use mc_transaction_types::TokenId;
