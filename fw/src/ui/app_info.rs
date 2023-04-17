// Copyright (c) 2022-2023 The MobileCoin Foundation

use emstr::{helpers::Hex, EncodeStr};
use rand_core::{CryptoRng, RngCore};

use nanos_sdk::buttons::ButtonEvent;
use nanos_ui::{
    layout::{Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::{
    apdu::app_info::AppFlags,
    engine::{Driver, Engine},
};

use super::{clear_screen, UiResult};
use crate::consts::{app_flags, APP_VERSION, BUILD_TIME};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct AppInfo {}

impl AppInfo {
    pub fn new() -> Self {
        Self {}
    }

    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult {
        match btn {
            // Exit on both buttons pressed/released
            ButtonEvent::BothButtonsRelease => UiResult::Exit(()),
            // Otherwise, no change
            _ => UiResult::None,
        }
    }

    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, engine: &Engine<D, R>) {
        let mut buff = [0u8; 32];

        // Clear screen
        clear_screen();

        let state = engine.state();
        let s = u16::from_be_bytes([state.state() as u8, state.value() as u8]);

        let mut flags = app_flags();

        if engine.is_unlocked() {
            flags |= AppFlags::UNLOCKED;
        }

        let state_str = emstr::write!(
            &mut buff[..],
            "S: 0x",
            Hex(&s.to_be_bytes()),
            " F: 0x",
            Hex(&flags.bits().to_be_bytes())
        )
        .map(|n| core::str::from_utf8(&buff[..n]));

        let state_str = match state_str {
            Ok(Ok(v)) => v,
            _ => "INVALID_UTF8",
        };

        [APP_VERSION, BUILD_TIME, state_str].place(Location::Middle, Layout::Centered, false);

        // Update screen
        screen_util::screen_update();
    }
}
