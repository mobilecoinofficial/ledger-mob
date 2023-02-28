// Copyright (c) 2022-2023 The MobileCoin Foundation

use emstr::{helpers::Hex, EncodeStr};
use rand_core::{CryptoRng, RngCore};
use strum::EnumCount;

use mc_core::{account::RingCtAddress, consts::DEFAULT_SUBADDRESS_INDEX, subaddress::Subaddress};

use nanos_sdk::buttons::ButtonEvent;

use nanos_ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::{
    apdu::app_info::AppFlags,
    engine::{Driver, Engine},
};

use super::{clear_screen, helpers::*, UiResult};
use crate::consts::{app_flags, APP_VERSION, BUILD_TIME, MOB32X32};

#[derive(Copy, Clone, Debug, PartialEq, EnumCount)]
pub enum MenuState {
    Hello,
    SpendAddress,
    ViewAddress,
    Version,
    Exit,
}

#[derive(Default)]
pub struct UiMenu {
    // Current menu page index
    i: usize,
    // Flag for menu page selection
    selected: bool,
}

pub const MENU_STATES: &[MenuState] = &[
    MenuState::Hello,
    MenuState::SpendAddress,
    MenuState::ViewAddress,
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

    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult {
        // Menu button handling
        match (self.state(), btn) {
            // Select on exit exits app
            (MenuState::Exit, ButtonEvent::BothButtonsRelease) => nanos_sdk::exit_app(20),

            // Select on home does nothing
            (MenuState::Hello, ButtonEvent::BothButtonsRelease) => return UiResult::None,

            // Otherwise, select enters / exits screens
            (_, ButtonEvent::BothButtonsRelease) => {
                self.selected = !self.selected;
            }

            // Scroll right and left in menu
            (_, ButtonEvent::RightButtonRelease) if !self.selected => self.next(),
            (_, ButtonEvent::LeftButtonRelease) if !self.selected => self.prev(),

            _ => return UiResult::None,
        }

        UiResult::Update
    }

    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, engine: &Engine<D, R>) {
        let mut buff = [0u8; 32];
        let state = self.state();

        // Clear screen
        clear_screen();

        // Show arrows on menu pages
        if state != MenuState::Hello && !self.selected {
            LEFT_ARROW.display();
            RIGHT_ARROW.display();
        }

        // Render pages
        match (state, self.selected) {
            (MenuState::Hello, _) => {
                "M O B I L E C O I N".place(Location::Custom(8), Layout::Centered, false);
                MOB32X32.draw((128 - 32) / 2, 24);
            }
            (MenuState::SpendAddress, false) => {
                "Spend Subaddress".place(Location::Middle, Layout::Centered, false);
            }
            (MenuState::SpendAddress, true) => {
                let default_subaddress = engine.get_account(0).subaddress(DEFAULT_SUBADDRESS_INDEX);
                let key = default_subaddress.spend_public_key();
                show_key("Spend Subaddress", &key.to_bytes());
            }
            (MenuState::ViewAddress, false) => {
                "View Subaddress".place(Location::Middle, Layout::Centered, false);
            }
            (MenuState::ViewAddress, true) => {
                let default_subaddress = engine.get_account(0).subaddress(DEFAULT_SUBADDRESS_INDEX);
                let key = default_subaddress.view_public_key();
                show_key("View Subaddress", &key.to_bytes());
            }
            (MenuState::Version, false) => {
                "App Info".place(Location::Middle, Layout::Centered, false);
            }
            (MenuState::Version, true) => {
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

                [APP_VERSION, BUILD_TIME, state_str].place(
                    Location::Middle,
                    Layout::Centered,
                    false,
                );
            }
            (MenuState::Exit, _) => "Exit".place(Location::Middle, Layout::Centered, false),
        }

        // Update screen
        screen_util::screen_update();
    }
}
