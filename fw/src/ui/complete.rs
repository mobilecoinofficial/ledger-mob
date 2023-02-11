// Copyright (c) 2022-2023 The MobileCoin Foundation

use rand_core::{CryptoRng, RngCore};

use nanos_sdk::buttons::ButtonEvent;

use nanos_ui::{
    layout::{Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::engine::{Driver, Engine};

use super::{clear_screen, UiResult};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Complete;

impl Complete {
    pub fn new() -> Self {
        Self
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
        "Transaction Complete".place(Location::Middle, Layout::Centered, false);

        // Update screen
        screen_util::screen_update();
    }
}
