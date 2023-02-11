// Copyright (c) 2022-2023 The MobileCoin Foundation

use rand_core::{CryptoRng, RngCore};

use nanos_sdk::buttons::ButtonEvent;

use nanos_ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::engine::{Driver, Engine, State};

use super::{clear_screen, UiResult};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Progress;

impl Progress {
    pub fn new() -> Self {
        Self
    }

    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<bool> {
        match btn {
            // Cancel current operation on both buttons pressed/released
            ButtonEvent::BothButtonsRelease => UiResult::Exit(false),
            // Otherwise, no change
            _ => UiResult::None,
        }
    }

    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, engine: &Engine<D, R>) {
        // Clear screen
        clear_screen();

        // Resolve message based on engine state
        let message = match engine.state() {
            #[cfg(feature = "summary")]
            State::Summary(_) => "Loading Transaction",
            #[cfg(feature = "mlsag")]
            State::SignRing(_) => "Signing Transaction",
            _ => "UNKNOWN",
        };

        // Render progress information
        match engine.progress() {
            Some(v) => {
                let v = v as u32;

                message.place(Location::Custom(16), Layout::Centered, false);

                // Fill progress bar + border
                RectFull::new().width(102).height(10).pos(13, 36).display();
                // Clear null-space based on progress
                RectFull::new()
                    .width(100 - v)
                    .height(8)
                    .pos(14 + v as i32, 37)
                    .erase();
            }
            _ => {
                message.place(Location::Middle, Layout::Centered, false);
            }
        }

        // Update screen
        screen_util::screen_update();
    }
}
