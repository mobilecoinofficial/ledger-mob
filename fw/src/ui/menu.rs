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
use crate::consts::MOB32X32;

#[derive(Copy, Clone, Debug, PartialEq, EnumCount)]
pub enum MenuState {
    Hello,
    Address,
    Version,
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
    MenuState::Exit,
];

impl UiMenu {
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
                "M O B I L E C O I N".place(Location::Custom(8), Layout::Centered, false);
                MOB32X32.draw((128 - 32) / 2, 24);
            }
            MenuState::Address => {
                "Address".place(Location::Middle, Layout::Centered, false);
            }
            MenuState::Version => {
                "App Info".place(Location::Middle, Layout::Centered, false);
            }
            MenuState::Exit => "Exit".place(Location::Middle, Layout::Centered, false),
        }

        // Update screen
        screen_util::screen_update();
    }
}
