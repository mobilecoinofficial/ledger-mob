#![no_std]
// Copyright (c) 2022-2023 The MobileCoin Foundation
#![no_main]
#![cfg_attr(feature = "alloc", feature(alloc_error_handler))]

extern crate rlibc;

#[cfg(feature = "alloc")]
extern crate alloc;

use core::mem::MaybeUninit;

use encdec::Encode;
use rand_core::{CryptoRng, RngCore};

use nanos_sdk::{
    buttons::ButtonEvent,
    io::{self, Reply, SyscallError},
    random::LedgerRng,
};
use nanos_ui::{
    layout::{Layout, Location, StringPlace},
    screen_util::screen_update,
};

use ledger_mob_core::{
    apdu::{self, app_info::AppFlags},
    engine::{Engine, Error, Event, State},
};

mod consts;
use consts::*;

mod platform;
use platform::*;

mod ui;
use ui::*;

const APDU_HEADER_LEN: usize = 5;

/// Engine context is global to mitigate stack-related issues in ledger fw,
/// expect this to be resolved in future but, the workaround is not egregious...
/// (in current releases if you use >8k of _stack_ all syscalls fail, as distinct
/// from using too much _memory_ which would also be a problem)
static mut ENGINE_CTX: MaybeUninit<Engine<LedgerDriver, LedgerRng>> = MaybeUninit::uninit();

// Setup ledger panic handler
nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

// Setup custom (OS) getrandom function
getrandom::register_custom_getrandom!(app_getrandom);

// Bind getrandom via nanos_sdk call
#[no_mangle]
#[inline]
pub fn app_getrandom(buff: &mut [u8]) -> Result<(), getrandom::Error> {
    nanos_sdk::random::rand_bytes(buff);
    Ok(())
}

#[no_mangle]
extern "C" fn sample_main() {
    // Setup comms and UI instances
    let mut comm = io::Comm::new();
    let mut ui = Ui::new();

    let mut ticks = 0u32;
    let mut timeout = TIMEOUT_S * TICKS_PER_S;

    let mut redraw = true;

    #[cfg(feature = "alloc")]
    platform::allocator::init();

    // Bind engine context
    let engine = unsafe {
        ENGINE_CTX.write(Engine::new_with_rng(LedgerDriver {}, LedgerRng {}));
        &mut *ENGINE_CTX.as_mut_ptr()
    };

    // Developer mode / pending review popup
    // must be cleared with user interaction
    #[cfg(feature = "pre-release")]
    {
        use ButtonEvent::*;

        clear_screen();
        "Pending Review".place(Location::Middle, Layout::Centered, false);
        screen_update();

        loop {
            let evt = comm.next_event::<u8>();

            match evt {
                io::Event::Button(LeftButtonRelease | RightButtonRelease | BothButtonsRelease) => break,
                io::Event::Command(_cmd) => {
                    comm.reply(SyscallError::Security);
                }
                _ => (),
            }
        }
    }

    // Run platform tests prior to init
    platform_tests(&mut comm);

    loop {
        // Wait for next event
        let evt = comm.next_event();

        // Handle input events and update UI state
        match &evt {
            // Handle button presses
            io::Event::Button(btn) => {
                if handle_btn(engine, &mut comm, &mut ui, btn) {
                    redraw = true
                }

                // Update timeout on button press
                timeout = ticks.wrapping_add(TIMEOUT_S * TICKS_PER_S);
            }
            // Handle incoming APDUs
            io::Event::Command(cmd) => {
                if handle_apdu(engine, &mut comm, &mut ui, *cmd) {
                    redraw = true;
                }
            }
            // Handle ticks
            io::Event::Ticker => {
                // Update tick counter
                ticks = ticks.wrapping_add(1);

                // Exit on timeout
                if ticks == timeout {
                    nanos_sdk::exit_app(13)
                }
            }
        };

        // Redraw UI on state change
        if redraw {
            ui.render(&*engine);
            redraw = false;
        }
    }
}

/// Handle button events, returning true if UI should be redrawn
#[inline]
fn handle_btn<RNG: RngCore + CryptoRng>(
    engine: &mut Engine<LedgerDriver, RNG>,
    _comm: &mut io::Comm,
    ui: &mut Ui,
    btn: &ButtonEvent,
) -> bool {
    // Handle buttons depending on UI state
    let r = match ui.state {
        UiState::Menu => ui.menu.update(btn),
        UiState::KeyRequest(ref mut a) => {
            a.update(btn).map_exit(|v| {
                // Unlock engine on approval
                if *v {
                    engine.unlock()
                }
            })
        }
        #[cfg(feature = "ident")]
        UiState::IdentRequest(ref mut a) => {
            a.update(btn).map_exit(|v| {
                // Set ident approval
                engine.ident_approve(*v)
            })
        }
        UiState::TxRequest(ref mut a) => {
            a.update(btn).map_exit(|v| {
                // Approve or deny transaction
                match *v {
                    true => engine.approve(),
                    false => engine.deny(),
                }
            })
        }
        #[cfg(feature = "summary")]
        UiState::TxSummaryRequest(ref mut a) => {
            a.update(btn).map_exit(|v| {
                // Approve or deny transaction
                match *v {
                    true => engine.approve(),
                    false => engine.deny(),
                }
            })
        }
        UiState::Progress(ref mut a) => {
            a.update(btn).map_exit(|v| {
                // Cancel transaction in progress
                match *v {
                    true => (),
                    false => engine.deny(),
                }
            })
        }
        UiState::Complete(ref mut a) => {
            a.update(btn).map_exit(|_| {
                // Reset engine on exit
                engine.reset()
            })
        }
    };

    // Handle ui results
    match ui.state {
        UiState::KeyRequest(..)
        | UiState::TxRequest(..)
        | UiState::Progress(..)
        | UiState::Complete(..)
            if r.is_exit() =>
        {
            ui.state = UiState::Menu;
            true
        }
        #[cfg(feature = "summary")]
        UiState::TxSummaryRequest(..) if r.is_exit() => {
            ui.state = UiState::Menu;
            true
        }
        #[cfg(feature = "ident")]
        UiState::IdentRequest(..) if r.is_exit() => {
            ui.state = UiState::Menu;
            true
        }
        _ => r == UiResult::Update,
    }
}

/// Handle APDU commands, returning true if UI should be redrawn
#[inline]
fn handle_apdu<RNG: RngCore + CryptoRng>(
    engine: &mut Engine<LedgerDriver, RNG>,
    comm: &mut io::Comm,
    ui: &mut Ui,
    i: u8,
) -> bool {
    use apdu::*;

    let mut render = false;

    // Skip empty APDUs
    if comm.rx == 0 {
        return false;
    }

    // Handle generic commands
    if i == app_info::AppInfoReq::INS {
        let mut flags = app_flags();
        flags.set(AppFlags::UNLOCKED, engine.is_unlocked());

        let i = app_info::AppInfoResp::new(MOB_PROTO_VERSION, APP_NAME, APP_VERSION, flags);

        match i.encode(&mut comm.apdu_buffer) {
            Ok(n) => {
                comm.tx = n;
                comm.reply_ok();
            }
            Err(_e) => {
                let r = 0x6d00 | (Error::EncodingFailed as u8) as u16;
                comm.reply(Reply(r));
            }
        }

        return false;
    }

    // Handle engine / transaction commands

    // Decode APDUs to engine events
    let evt = match Event::parse(i, &comm.apdu_buffer[APDU_HEADER_LEN..]) {
        Ok(v) => v,
        Err(_e) => {
            comm.reply(SyscallError::InvalidParameter);
            return false;
        }
    };

    // WIP: user acknowledgement screens etc.
    // to be moved once i've worked out how to wire this best

    match evt {
        Event::GetWalletKeys { .. }
        | Event::GetSubaddressKeys { .. }
        | Event::GetKeyImage { .. }
            if !engine.is_unlocked() && !ui.state.is_key_request() =>
        {
            // Update UI to key request acknowledge state
            ui.state = UiState::KeyRequest(Approver::new(APPROVE_KEY_REQ));

            // Return empty APDU to signify late response
            // TODO: check on how other apps do this
            comm.tx = 0;
            comm.reply_ok();

            return true;
        }
        _ => (),
    }

    // Update engine
    let r = match engine.update(&evt) {
        Ok(v) => v,
        Err(e) => {
            let r = 0x6d00 | (e as u8) as u16;
            comm.reply(Reply(r));
            return false;
        }
    };

    // Update UI based on engine state changes
    match engine.state() {
        // Update to identity approval on request
        #[cfg(feature = "ident")]
        State::Ident(s) if s.is_pending() && !ui.state.is_ident_request() => {
            ui.state = UiState::IdentRequest(IdentApprover::new());
            render = true;
        }

        // Update to progress while loading transaction
        #[cfg(feature = "summary")]
        State::Summary(..) if !ui.state.is_progress() => {
            ui.state = UiState::Progress(Progress::new());
            render = true;
        }

        // Update to TX approval UI when engine state is pending
        State::Pending if !ui.state.is_tx_request() => match engine.report() {
            #[cfg(feature = "summary")]
            Some(r) => {
                ui.state =
                    UiState::TxSummaryRequest(TxSummaryApprover::new(r.balance_changes.len()));
                render = true;
            }
            _ => {
                ui.state = UiState::TxRequest(TxBlindApprover::new());
                render = true;
            }
        },

        // Update to progress while signing transaction
        State::SignRing(..) if !ui.state.is_progress() => {
            ui.state = UiState::Progress(Progress::new());
            render = true;
        }

        // Update to complete when transaction is complete
        State::Complete if !ui.state.is_complete() => {
            ui.state = UiState::Complete(Complete::new());
            render = true;
        }

        _ => (),
    }

    // Re-render progress bars on updates
    if ui.state.is_progress() {
        render = true;
    }

    // Encode engine output to response APDU
    let n = match r.encode(&mut comm.apdu_buffer) {
        Ok(v) => v,
        Err(_e) => {
            comm.reply(SyscallError::Overflow);
            return false;
        }
    };

    // Send response
    comm.tx = n;
    comm.reply_ok();

    // Return render flag
    render
}

const APPROVE_KEY_REQ: &str = "Sync View Keys?";

fn platform_tests(comm: &mut io::Comm) {
    clear_screen();

    // Ensure RNG is operating as expected
    let mut b = [0xFE; 32];
    LedgerRng {}.fill_bytes(&mut b);

    if b == [0xFE; 32] || b == [0x00; 32] {
        "ERROR".place(Location::Top, Layout::Centered, true);
        "RNG UNAVAILABLE".place(Location::Middle, Layout::Centered, false);
        "EXIT?".place(Location::Bottom, Layout::Centered, false);

        loop {
            let evt = comm.next_event::<u8>();

            match evt {
                io::Event::Button(_btn) => nanos_sdk::exit_app(30),
                io::Event::Command(_cmd) => {
                    comm.reply(SyscallError::Security);
                }
                _ => (),
            }
        }
    }

    // Test allocator
    #[cfg(feature = "alloc")]
    {
        let v = alloc::vec![0x11, 0x22, 0x33];
        drop(v);
    }
}
