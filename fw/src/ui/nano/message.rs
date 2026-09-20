// Copyright (c) 2022-2023 The MobileCoin Foundation

use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::buttons::ButtonEvent;

use ledger_device_sdk::ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::engine::{Driver, Engine};

use super::{clear_screen, UiResult};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Message {
    value: &'static str,
    success: bool,
}

impl Message {
    pub fn new(value: &'static str, success: bool) -> Self {
        Self { value, success }
    }

    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<bool> {
        match btn {
            // Exit on both buttons pressed/released
            ButtonEvent::BothButtonsRelease => UiResult::Exit(false),
            // Otherwise, no change
            _ => UiResult::None,
        }
    }

    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, _engine: &Engine<D, R>) {
        // Clear screen
        clear_screen();

        // Render transaction information
        self.value
            .place(Location::Custom(14), Layout::Centered, false);

        // Render success / error icon
        match self.success {
            true => CHECKMARK_ICON.shift_v(6).shift_h((128 - 16) / 2).display(),
            false => CROSS_ICON.shift_v(6).shift_h((128 - 16) / 2).display(),
        }

        // Update screen
        screen_util::screen_update();
    }
}
