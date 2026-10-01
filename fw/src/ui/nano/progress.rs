// Copyright (c) 2022-2023 The MobileCoin Foundation

use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::buttons::ButtonEvent;

use ledger_device_sdk::ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use super::{clear_screen, UiResult};
use ledger_mob_core::engine::{Driver, Engine, State};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Progress {
    init: bool,
    message: &'static str,
}

impl Progress {
    /// Create a new [Progress] instance
    pub fn new(message: &'static str) -> Self {
        Self { init: false, message }
    }

    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<bool> {
        match btn {
            // Cancel current operation on both buttons pressed/released
            ButtonEvent::BothButtonsRelease => UiResult::Exit(false),
            // Otherwise, no change
            _ => UiResult::None,
        }
    }

    pub fn render<D: Driver, R: RngCore + CryptoRng>(&mut self, engine: &Engine<D, R>) {
        // Run full screen setup on first render
        if !self.init {
            clear_screen();
            // Fill progress bar + border
            RectFull::new().width(102).height(10).pos(13, 36).display();
            // Clear null-space based on progress
            RectFull::new().width(100).height(8).pos(14_i32, 37).erase();

            self.init = true;
        }

        // Render progress information
        match engine.progress() {
            Some(v) => {
                let v = v as u32;

                self.message.place(Location::Custom(16), Layout::Centered, false);

                // Fill progress bar and clear null-space based on progress
                RectFull::new().width(v).height(8).pos(14_i32, 37).display();
                RectFull::new()
                    .width(100 - v)
                    .height(8)
                    .pos(14 + v as i32, 37)
                    .erase();
            }
            _ => {
                self.message.place(Location::Middle, Layout::Centered, false);
            }
        }

        // Update screen
        screen_util::screen_update();
    }
}
