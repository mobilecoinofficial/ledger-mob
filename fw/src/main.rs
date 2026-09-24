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

use ledger_device_sdk::{
    io::{self, ApduHeader, Reply, SyscallError},
    random::LedgerRng,
};
use ledger_proto::apdus::{AppFlags, AppInfoReq, AppInfoResp, DeviceInfoReq};

#[cfg(feature = "ident")]
use ledger_mob_core::engine::IdentState;
use ledger_mob_core::{
    apdu::{self, app_info::AppFlags as MobAppFlags, tx::FogId},
    engine::{Engine, EngineAppInfo, Error, Event, Output, State},
};

mod consts;
use consts::*;

mod platform;
use platform::*;

mod ui;
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
use ui::nano::*;
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
use ui::touch::*;

#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
mod settings;

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
    let mut message_timeout = None;

    let mut redraw = true;

    // Bind the comm to the nbgl
    #[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
    ledger_device_sdk::nbgl::init_comm(&mut comm);

    #[cfg(feature = "debug")]
    ledger_device_sdk::log::debug!(
        "Start app: {} v{} (git: {}, build: {})",
        APP_NAME,
        APP_VERSION,
        GIT_VERSION,
        BUILD_TIME
    );

    // non-nvm fog ID global must be pre-initialised
    #[cfg(not(feature = "nvm"))]
    platform::platform_set_fog_id(&FogId::MobMain);

    #[cfg(feature = "summary")]
    let base_flags = MobAppFlags::HAS_TX_SUMMARY;
    #[cfg(not(feature = "summary"))]
    let base_flags = MobAppFlags::empty();

    let app_info = EngineAppInfo {
        app_name: APP_NAME,
        app_version: APP_VERSION,
        git_version: GIT_VERSION,
        base_flags,
    };

    // Initialise and bind globally allocated contexts
    let (engine, ui, event, output) = unsafe {
        let p = &mut *APP_CTX.as_mut_ptr();

        Engine::init(&mut p.engine, LedgerDriver {}, LedgerRng {}, app_info);
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

        // TODO: all this could be in the UI module?
        clear_screen();
        show_pending_review();
        #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
        screen_update();
    }

    // Run platform tests prior to init
    platform_tests(&mut comm);

    loop {
        // Wait for next event
        let evt = comm.next_event::<ApduHeader>();

        // Handle input events and update UI state
        match &evt {
            // Handle button presses
            #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
            io::Event::Button(btn) => {
                if ui.handle_btn(engine, btn) {
                    // Set redraw flag on changes
                    redraw = true
                }

                // Update screen lock timeout on any button press
                lock_timeout = ticks.wrapping_add(LOCK_TIMEOUT_S * TICKS_PER_S);
            }

            #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
            io::Event::TouchEvent => {
                // Handle touch events and update UI state
                if ui.handle_touch(engine) {
                    redraw = true;
                }

                // Update screen lock timeout on any touch event
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
                // `None` signifies that the timer is not armed.
                if ui.state.is_message() && message_timeout.is_some_and(|timeout| ticks == timeout)
                {
                    // Reset to menu state
                    ui.state = UiState::menu();
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

        // Arm the message timer if it's disarmed and we have entered the message state,
        // disarm it in any other state.
        // NOTE: this check is because on touch devices the render function can change states.
        // NOTE: if a new message was entered from directly from the message state
        // this would not be reset, but, we never do that.
        match ui.state.is_message() {
            true if message_timeout.is_none() => {
                // `.max(1)` avoids a wrapped deadline colliding with the unarmed state
                message_timeout = Some(ticks.wrapping_add(MESSAGE_TIMEOUT_S * TICKS_PER_S).max(1));
            }
            false => message_timeout = None,
            _ => (),
        }

        // Redraw UI on state change
        // NOTE: on touch devices this can also mutate the engine state
        if redraw {
            ui.render(&mut *engine);
            redraw = false;
        }
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
            match r.encode(&mut comm.io_buffer) {
                Ok(n) => {
                    comm.tx_length = n;
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
            match fetch_encode_device_info(&mut comm.io_buffer) {
                Ok(n) => {
                    comm.tx_length = n;
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
            ui.state = UiState::key_request();

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
            ui.state = UiState::ident_request();
            render = true;
        }
        // Show identity state on changes
        #[cfg(feature = "ident")]
        State::Ident(IdentState::Approved) => {
            if !ui.state.is_message() {
                ui.state = UiState::message("challenge approved", true);
                render = true;
            }
        }
        #[cfg(feature = "ident")]
        State::Ident(IdentState::Denied) => {
            if !ui.state.is_message() {
                ui.state = UiState::message("challenge rejected", false);
                render = true;
            }
        }

        // Update to progress while loading transaction
        #[cfg(feature = "summary")]
        State::Summary(..) if !ui.state.is_progress() => {
            ui.state = UiState::progress();
            render = true;
        }

        // Update to TX approval UI when engine state is pending
        State::Pending if !ui.state.is_tx_request() => match engine.report() {
            #[cfg(feature = "summary")]
            Some(r) => {
                ui.state = UiState::tx_summary_request(r.outputs.len(), r.totals.len());
                render = true;
            }
            _ => {
                ui.state = UiState::tx_blind_request();
                render = true;
            }
        },

        // Update to progress while signing transaction
        State::SignRing(..) if !ui.state.is_progress() => {
            ui.state = UiState::progress();
            render = true;
        }

        // Set complete message when transaction is complete
        State::Complete if !ui.state.is_message() => {
            ui.state = UiState::message("Transaction Complete", true);
            render = true;
        }

        // Set cancelled message when transaction is aborted
        State::Deny if !ui.state.is_message() => {
            ui.state = UiState::message("Transaction Cancelled", false);
            render = true;
        }

        _ => (),
    }

    // Re-render progress bars on updates
    if ui.state.is_progress() {
        render = true;
    }

    // Encode engine output to response APDU
    let n = match output.encode(&mut comm.io_buffer) {
        Ok(v) => v,
        Err(_e) => {
            comm.reply(SyscallError::Overflow);
            return false;
        }
    };

    // Send response
    comm.tx_length = n;
    comm.reply_ok();

    // Return render flag
    render
}

#[cfg_attr(feature = "noinline", inline(never))]
fn platform_tests(comm: &mut io::Comm) {
    clear_screen();

    // Ensure RNG is operating as expected
    if let Err(_e) = test_rng() {
        // TODO(ryan): this will become a blocking UI call and exit for touch devices?
        show_rng_error();

        loop {
            let evt = comm.next_event::<ApduHeader>();

            match evt {
                #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
                io::Event::Button(_btn) => ledger_device_sdk::exit_app(30),
                #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
                io::Event::TouchEvent => ledger_device_sdk::exit_app(30),
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
