// Copyright (c) 2022-2023 The MobileCoin Foundation

use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::buttons::ButtonEvent;
use ledger_device_sdk::ui::{
    layout::{Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::engine::{Driver, Engine};

use super::{clear_screen, UiResult};
use crate::consts::{BUILD_TIME, GIT_VERSION};

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

    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, _engine: &Engine<D, R>) {
        // Clear screen
        clear_screen();

        // Show git version and build time
        [GIT_VERSION, BUILD_TIME].place(Location::Middle, Layout::Centered, false);

        // Update screen
        screen_util::screen_update();
    }
}
