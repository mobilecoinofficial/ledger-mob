//! Settings page for application UI
//!

use rand_core::{CryptoRng, RngCore};

use nanos_sdk::buttons::ButtonEvent;
use nanos_ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::{
    apdu::tx::{FogId, FOG_IDS},
    engine::{Driver, Engine},
};

use super::{clear_screen, UiResult};

/// [Settings] page, at the moment this only provides Fog configuration
#[derive(PartialEq, Clone, Debug)]
pub struct Settings {
    fog_id_index: usize,
}

impl Settings {
    pub fn new(fog_id: FogId) -> Self {
        let fog_id_index = fog_id as usize;
        Self { fog_id_index }
    }

    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<FogId> {
        match btn {
            // Exit on both buttons pressed/released
            ButtonEvent::BothButtonsRelease => UiResult::Exit(FOG_IDS[self.fog_id_index]),

            // Otherwise move through fogs
            ButtonEvent::LeftButtonRelease if self.fog_id_index > 0 => {
                self.fog_id_index -= 1;
                UiResult::Update
            }
            ButtonEvent::RightButtonRelease if self.fog_id_index < FOG_IDS.len() - 1 => {
                self.fog_id_index += 1;
                UiResult::Update
            }

            // Otherwise, no change
            _ => UiResult::None,
        }
    }

    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, _engine: &Engine<D, R>) {
        // Clear screen
        clear_screen();

        // Show arrows
        if self.fog_id_index > 0 {
            LEFT_ARROW.shift_v(0).display();
        }
        if self.fog_id_index < FOG_IDS.len() - 1 {
            RIGHT_ARROW.shift_v(0).display();
        }

        // Resolve index to fog ID and string
        let fog = FOG_IDS[self.fog_id_index];
        let name = fog_name(fog);

        // Display current selection
        "Fog ID".place(Location::Custom(8), Layout::Centered, false);
        name.place(Location::Custom(26), Layout::Centered, false);

        // Update screen
        screen_util::screen_update();
    }
}

/// Resolve fog_id to string for display
fn fog_name(fog_id: FogId) -> &'static str {
    match fog_id {
        FogId::None => "None",
        FogId::MobMain => "MobileCoin MainNet",
        FogId::MobTest => "MobileCoin TestNet",
        FogId::SignalMain => "Signal MainNet",
        FogId::SignalTest => "Signal TestNet",
    }
}
