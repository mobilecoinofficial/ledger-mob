// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ledger MobileCoin App Constants

#![allow(unused)]

use nanos_sdk::ecc::make_bip32_path;
use nanos_ui::bitmaps::Glyph;

use ledger_mob_core::apdu::app_info::AppFlags;

/// App Information
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_VERSION: &str = env!("GIT_TAG");
pub const BUILD_TIME: &str = env!("BUILD_TIME");
pub const APP_FLAGS: AppFlags = app_flags();

const fn app_flags() -> AppFlags {
    #[cfg(feature = "summary")]
    return AppFlags::HAS_TX_SUMMARY;

    #[cfg(not(feature = "summary"))]
    return AppFlags::empty();
}

/// Application timeout (exit after no user input)
pub const TIMEOUT_S: u32 = 5 * 60;

/// Ticks per second for calculating application timeouts
pub const TICKS_PER_S: u32 = 10;

/// BIP32 configuration
pub const BIP32_PATH: [u32; 5] = make_bip32_path(b"m/44'/866'/0'/0/0");

/// Mob logo in 14x14 (see build.rs for conversion)
pub const MOB14X14: Glyph = include!(concat!(env!("OUT_DIR"), "/mob14x14.gif"));

/// Mob logo in 16x16 (see build.rs for conversion)
pub const MOB16X16: Glyph = include!(concat!(env!("OUT_DIR"), "/mob16x16.gif"));

/// Mob logo in 32x32 (see build.rs for conversion)
pub const MOB32X32: Glyph = include!(concat!(env!("OUT_DIR"), "/mob32x32.gif"));
