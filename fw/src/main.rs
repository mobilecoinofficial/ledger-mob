// Copyright (c) 2022-2023 The MobileCoin Foundation

#![no_std]
#![no_main]
#![cfg_attr(feature = "alloc", feature(alloc_error_handler))]

extern crate rlibc;

#[cfg(feature = "alloc")]
extern crate alloc;

use core::mem::MaybeUninit;

use encdec::Encode;
use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::ui::layout::{Layout, Location, StringPlace};
use ledger_device_sdk::{
    buttons::ButtonEvent,
    io::{self, ApduHeader, Reply, SyscallError},
    random::LedgerRng,
};
use ledger_proto::apdus::{AppFlags, AppInfoReq, AppInfoResp, DeviceInfoReq};

use ledger_mob_core::{
    apdu::{
        self,
        app_info::{
            AppFlags as MobAppFlags, AppInfoReq as MobAppInfoReq, AppInfoResp as MobAppInfoResp,
        },
        tx::FogId,
    },
    engine::{Engine, Error, Event, IdentState, Output, State},
};
use mc_core::consts::DEFAULT_SUBADDRESS_INDEX;

mod consts;
use consts::*;

mod platform;
use platform::*;

mod ui;
use ui::*;

const APDU_HEADER_LEN: usize = 5;

/// Engine context is global to mitigate stack-related issues in current ledger OS.
/// (in current releases if you use >8k of _stack_ on the nanosplus syscalls will
/// fail while on the nanox all memory access will fail)
/// This is exacerbated by rust/llvm failing to support NRVO or copy-elision
/// expect this to be resolved in the OS in future but, the workaround is not egregious...
static mut APP_CTX: MaybeUninit<AppCtx> = MaybeUninit::uninit();

/// Container for app context to simplify global init
struct AppCtx {
    engine: Engine<LedgerDriver, LedgerRng>,
    ui: Ui,
    event: Event,
    output: Output,
}

// Setup ledger panic handler
ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

// Setup custom (OS) getrandom function
getrandom::register_custom_getrandom!(app_getrandom);

// Bind getrandom via nanos_sdk call
#[no_mangle]
#[inline]
pub fn app_getrandom(buff: &mut [u8]) -> Result<(), getrandom::Error> {
    ledger_device_sdk::random::rand_bytes(buff);
    Ok(())
}

#[no_mangle]
extern "C" fn sample_main() {
    // Setup comms and UI instances
    let mut comm = io::Comm::new();

    let mut ticks = 0u32;
    let mut lock_timeout = LOCK_TIMEOUT_S * TICKS_PER_S;
    let mut message_timeout = 0;

    let mut redraw = true;

    #[cfg(feature = "alloc")]
    platform::allocator::init();

    // non-nvm fog ID global must be pre-initialised
    #[cfg(not(feature = "nvm"))]
    platform::platform_set_fog_id(&FogId::MobMain);

    // Initialise and bind globally allocated contexts
    let (engine, ui, event, output) = unsafe {
        let p = &mut *APP_CTX.as_mut_ptr();

        Engine::init(&mut p.engine, LedgerDriver {}, LedgerRng {});
        Ui::init(&mut p.ui);
        Event::init(&mut p.event);
        Output::init(&mut p.output);

        (&mut p.engine, &mut p.ui, &mut p.event, &mut p.output)
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
            let evt = comm.next_event::<ApduHeader>();

            match evt {
                io::Event::Button(LeftButtonRelease | RightButtonRelease | BothButtonsRelease) => {
                    break
                }
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
        let evt = comm.next_event::<ApduHeader>();

        let last_state_is_message = ui.state.is_message();

        // Handle input events and update UI state
        match &evt {
            // Handle button presses
            io::Event::Button(btn) => {
                if handle_btn(engine, ui, btn) {
                    // Set redraw flag on changes
                    redraw = true
                }

                // Update timeout on button press
                lock_timeout = ticks.wrapping_add(LOCK_TIMEOUT_S * TICKS_PER_S);
            }
            // Handle incoming APDUs
            io::Event::Command(_hdr) => {
                if handle_apdu(engine, &mut comm, ui, event, output) {
                    // Set redraw flags on changes
                    redraw = true;
                }
            }
            // Handle ticks
            io::Event::Ticker => {
                // Update tick counter
                ticks = ticks.wrapping_add(1);

                // Return to menu state after message timeout
                if ui.state.is_message() && ticks >= message_timeout {
                    // Reset to menu state
                    ui.state = UiState::Menu;
                    redraw = true;

                    // Reset engine to init state
                    engine.reset();
                }

                // Request pin entry after lock timeout
                if ticks == lock_timeout {
                    // Clear engine approval flag
                    engine.lock();

                    // Execute lock syscall (blocks on pin entry)
                    request_pin_validation();

                    // Reset timeout and redraw on re-entry
                    lock_timeout = ticks.wrapping_add(LOCK_TIMEOUT_S * TICKS_PER_S);
                    redraw = true;
                }
            }
        };

        // Set message timer on state entry
        if !last_state_is_message && ui.state.is_message() {
            message_timeout = ticks.wrapping_add(MESSAGE_TIMEOUT_S * TICKS_PER_S);
        }

        // Redraw UI on state change
        if redraw {
            ui.render(&*engine);
            redraw = false;
        }
    }
}

/// Handle button events, returning true if UI should be redrawn
#[cfg_attr(feature = "noinline", inline(never))]
fn handle_btn<RNG: RngCore + CryptoRng>(
    engine: &mut Engine<LedgerDriver, RNG>,
    ui: &mut Ui,
    btn: &ButtonEvent,
) -> bool {
    // Handle buttons depending on UI state
    let r = match ui.state {
        UiState::Menu => {
            // Handle menu selections
            ui.menu.update(btn).map_exit(|v| {
                match v {
                    MenuState::Address => {
                        // Fetch subaddress from engine
                        let fog_id = platform_get_fog_id();
                        let s = engine.get_subaddress(0, DEFAULT_SUBADDRESS_INDEX, fog_id);

                        // Set UI state to display subaddress
                        ui.state = UiState::Address(Address::new(
                            &s.address,
                            s.fog_id,
                            s.fog_sig.as_ref().map(|s| s.as_slice()).unwrap_or(&[]),
                        ));
                    }
                    MenuState::Version => ui.state = UiState::AppInfo(AppInfo::new()),
                    MenuState::Settings => {
                        let fog_id = platform_get_fog_id();
                        ui.state = UiState::Settings(Settings::new(fog_id))
                    }
                    MenuState::Exit => ledger_device_sdk::exit_app(0),
                    _ => (),
                }
            });
            // Force redraw
            UiResult::Update
        }
        UiState::Address(ref mut a) => a.update(btn),
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
            a.update(btn, engine).map_exit(|v| {
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
        UiState::Message(ref mut a) => {
            a.update(btn).map_exit(|_| {
                // Reset engine on message clear
                engine.reset()
            })
        }
        UiState::AppInfo(ref mut a) => a.update(btn),
        UiState::Settings(ref mut a) => a.update(btn).map_exit(|fog_id| {
            // Update fog id
            platform_set_fog_id(fog_id);
        }),
    };

    // Handle ui results
    match ui.state {
        UiState::Address(..)
        | UiState::KeyRequest(..)
        | UiState::TxRequest(..)
        | UiState::Progress(..)
        | UiState::Message(..)
        | UiState::AppInfo(..)
        | UiState::Settings(..)
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
#[cfg_attr(feature = "noinline", inline(never))]
fn handle_apdu<RNG: RngCore + CryptoRng>(
    engine: &mut Engine<LedgerDriver, RNG>,
    comm: &mut io::Comm,
    ui: &mut Ui,
    evt: &mut Event,
    output: &mut Output,
) -> bool {
    use apdu::*;

    let mut render = false;

    // Skip empty / short APDUs
    if comm.rx < APDU_HEADER_LEN {
        return false;
    }

    // Read class and instruction
    let (cla, ins) = (comm.apdu_buffer[0], comm.apdu_buffer[1]);

    // Handle generic and ledger standard commands
    match (cla, ins) {
        // Ledger standard application info
        (AppInfoReq::CLA | 0, AppInfoReq::INS) => {
            let r = AppInfoResp::new(APP_NAME, APP_VERSION, AppFlags::empty());
            match r.encode(&mut comm.apdu_buffer) {
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
        // Ledger standard device info
        (DeviceInfoReq::CLA, DeviceInfoReq::INS) => {
            match fetch_encode_device_info(&mut comm.apdu_buffer) {
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
        // Ledger exit app command
        (0xb0, 0xa7) => {
            ledger_device_sdk::exit_app(0);
        }
        // MobileCoin application info
        (MobAppInfoReq::CLA, MobAppInfoReq::INS) => {
            let mut flags = app_flags();
            flags.set(MobAppFlags::UNLOCKED, engine.is_unlocked());

            let r = MobAppInfoResp::new(MOB_PROTO_VERSION, APP_NAME, APP_VERSION, flags);
            match r.encode(&mut comm.apdu_buffer) {
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
        _ => (),
    }

    // Return error for other unhandled APDUs
    if cla != MOB_APDU_CLA {
        comm.tx = 0;
        comm.reply(SyscallError::NotSupported);
        return false;
    }

    // Handle engine / transaction commands

    // Decode APDUs to engine events
    *evt = match Event::parse(ins, &comm.apdu_buffer[APDU_HEADER_LEN..]) {
        Ok(v) => v,
        Err(_e) => {
            comm.reply(SyscallError::InvalidParameter);
            return false;
        }
    };

    // WIP: user acknowledgement screens etc.
    // to be moved once i've worked out how to wire this best
    match &evt {
        Event::GetWalletKeys { .. }
        | Event::GetSubaddressKeys { .. }
        | Event::GetKeyImage { .. }
            if !engine.is_unlocked() && !ui.state.is_key_request() =>
        {
            // Update UI to key request acknowledge state
            ui.state = UiState::KeyRequest(SyncApprover::new());

            // Return empty APDU to signify late response
            // TODO: check on how other apps do this
            comm.tx = 0;
            comm.reply_ok();

            return true;
        }
        _ => (),
    }

    // Update engine
    *output = match engine.update(evt) {
        Ok(v) => v,
        Err(e) => {
            let r = 0x6d00 | (e as u8) as u16;
            comm.reply(Reply(r));
            return false;
        }
    };

    // Update UI based on engine state changes
    match engine.state() {
        // Update to identity approver on request
        #[cfg(feature = "ident")]
        State::Ident(IdentState::Pending) if !ui.state.is_ident_request() => {
            ui.state = UiState::IdentRequest(IdentApprover::new());
            render = true;
        }
        // Show identity state on changes
        #[cfg(feature = "ident")]
        State::Ident(IdentState::Approved) => {
            if !ui.state.is_message() {
                ui.state = UiState::message("challenge approved");
                render = true;
            }
        }
        #[cfg(feature = "ident")]
        State::Ident(IdentState::Denied) => {
            if !ui.state.is_message() {
                ui.state = UiState::message("challenge rejected");
                render = true;
            }
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
                ui.state = UiState::TxSummaryRequest(TxSummaryApprover::new(
                    r.outputs.len(),
                    r.totals.len(),
                ));
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

        // Set complete message when transaction is complete
        State::Complete if !ui.state.is_message() => {
            ui.state = UiState::message("Transaction Complete");
            render = true;
        }

        // Set cancelled message when transaction is aborted
        State::Deny if !ui.state.is_message() => {
            ui.state = UiState::message("Transaction Cancelled");
            render = true;
        }

        _ => (),
    }

    // Re-render progress bars on updates
    if ui.state.is_progress() {
        render = true;
    }

    // Encode engine output to response APDU
    let n = match output.encode(&mut comm.apdu_buffer) {
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

#[cfg_attr(feature = "noinline", inline(never))]
fn platform_tests(comm: &mut io::Comm) {
    clear_screen();

    // Ensure RNG is operating as expected
    if let Err(_e) = test_rng() {
        "ERROR".place(Location::Top, Layout::Centered, true);
        "RNG UNAVAILABLE".place(Location::Middle, Layout::Centered, false);
        "EXIT?".place(Location::Bottom, Layout::Centered, false);

        loop {
            let evt = comm.next_event::<ApduHeader>();

            match evt {
                io::Event::Button(_btn) => ledger_device_sdk::exit_app(30),
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
