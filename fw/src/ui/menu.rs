// Copyright (c) 2022-2023 The MobileCoin Foundation

use rand_core::{CryptoRng, RngCore};
use strum::EnumCount;

use nanos_sdk::buttons::ButtonEvent;
use nanos_ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::engine::{Driver, Engine};

use super::{clear_screen, UiResult};
use crate::consts::{APP_VERSION, MOB32X32};

#[derive(Copy, Clone, Debug, PartialEq, EnumCount)]
pub enum MenuState {
    Hello,
    Address,
    Version,
    Settings,
    Exit,
}

#[derive(Default)]
pub struct UiMenu {
    // Current menu page index
    i: usize,
}

pub const MENU_STATES: &[MenuState] = &[
    MenuState::Hello,
    MenuState::Address,
    MenuState::Version,
    MenuState::Settings,
    MenuState::Exit,
];

const ICON_OFFSET: i16 = -8;
const TEXT_OFFSET: usize = 34;

impl UiMenu {
    pub const fn new() -> Self {
        Self { i: 0 }
    }

    fn next(&mut self) {
        self.i = (self.i + 1) % MENU_STATES.len()
    }

    fn prev(&mut self) {
        self.i = (self.i + MENU_STATES.len() - 1) % MENU_STATES.len()
    }

    fn state(&self) -> MenuState {
        MENU_STATES[self.i]
    }

    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<MenuState> {
        // Menu button handling
        match (self.state(), btn) {
            // Otherwise, select enters screens
            (_, ButtonEvent::BothButtonsRelease) => return UiResult::Exit(self.state()),

            // Scroll right and left in menu
            (_, ButtonEvent::RightButtonRelease) => self.next(),
            (_, ButtonEvent::LeftButtonRelease) => self.prev(),

            _ => return UiResult::None,
        }

        UiResult::Update
    }

    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, _engine: &Engine<D, R>) {
        let state = self.state();

        // Clear screen
        clear_screen();

        // Show arrows on menu pages
        LEFT_ARROW.display();
        RIGHT_ARROW.display();

        // Render pages
        match state {
            MenuState::Hello => {
                MOB32X32.draw((128 - 32) / 2, 2);
                "MobileCoin".place(Location::Custom(38), Layout::Centered, true);
                "is ready".place(Location::Custom(50), Layout::Centered, false);
            }
            MenuState::Address => {
                CERTIFICATE_ICON
                    .shift_v(ICON_OFFSET)
                    .shift_h((128 - 16) / 2)
                    .display();
                "Address".place(Location::Custom(TEXT_OFFSET), Layout::Centered, true);
            }
            MenuState::Version => {
                "Version".place(Location::Custom(20), Layout::Centered, true);
                APP_VERSION.place(Location::Custom(36), Layout::Centered, false);
            }
            MenuState::Settings => {
                COGGLE_ICON
                    .shift_v(ICON_OFFSET)
                    .shift_h((128 - 16) / 2)
                    .display();
                "Settings".place(Location::Custom(TEXT_OFFSET), Layout::Centered, true);
            }
            MenuState::Exit => {
                DASHBOARD_X_ICON
                    .shift_v(ICON_OFFSET)
                    .shift_h((128 - 16) / 2)
                    .display();
                "Exit".place(Location::Custom(TEXT_OFFSET), Layout::Centered, true)
            }
        }

        // Update screen
        screen_util::screen_update();
    }
}
