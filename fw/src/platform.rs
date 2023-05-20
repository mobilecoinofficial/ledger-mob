// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ledger MobileCoin Platform Support

use ledger_mob_core::engine::Driver;
use nanos_sdk::{
    bindings::{os_perso_derive_node_with_seed_key, HDW_ED25519_SLIP10},
    ecc,
};

/// Ledger platform driver
pub struct LedgerDriver {}

impl Driver for LedgerDriver {
    /// SLIP-0010 ed25519 derivation from path via ledger syscall
    fn slip10_derive_ed25519(&self, path: &[u32]) -> [u8; 32] {
        let curve = ecc::CurvesId::Ed25519;
        let mut key = [0u8; 32];

        unsafe {
            os_perso_derive_node_with_seed_key(
                HDW_ED25519_SLIP10,
                curve as u8,
                path.as_ptr(),
                path.len() as u32,
                key.as_mut_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
            )
        };

        key
    }
}

// Global allocator configuration
#[cfg(feature = "alloc")]
pub(crate) mod allocator {
    use core::mem::MaybeUninit;
    use critical_section::RawRestoreState;

    /// Allocator heap size
    const HEAP_SIZE: usize = 1024;

    /// Statically allocated heap memory
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

    /// Bind global allocator
    #[global_allocator]
    static HEAP: embedded_alloc::Heap = embedded_alloc::Heap::empty();

    /// Error handler for allocation
    #[alloc_error_handler]
    fn oom(_: core::alloc::Layout) -> ! {
        nanos_sdk::exit_app(250)
    }

    /// Initialise allocator
    #[inline(never)]
    pub fn init() {
        unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
    }

    /// Noop critical section
    /// (_should_ okay as we only -have- one thread)
    struct MyCriticalSection;
    critical_section::set_impl!(MyCriticalSection);

    unsafe impl critical_section::Impl for MyCriticalSection {
        unsafe fn acquire() -> RawRestoreState {
            // nothing, it's all good, don't worry bout it
        }

        unsafe fn release(_token: RawRestoreState) {
            // nothing, it's all good, don't worry bout it
        }
    }
}

/// Timeout and request pin validation to unlock
// TODO: replace app exit with this behaviour
// TODO: timeout should also clear app auth flag for key operations
#[cfg(nyet)]
fn request_pin_validation() {
    let mut params = nanos_sdk::bindings::bolos_ux_params_t::default();
    params.ux_id = nanos_sdk::bindings::BOLOS_UX_VALIDATE_PIN;
    unsafe {
        nanos_sdk::bindings::os_ux(&params as *mut nanos_sdk::bindings::bolos_ux_params_t);
    }
}

/// Helper to print the current stack position, useful for diagnosing the 8kb stack limit
#[no_mangle]
#[inline(never)]
pub extern "C" fn print_stack() {
    use nanos_sdk::bindings::try_context_s;

    // Create a variable to fetch current stack pointer
    let p = 0u32;
    let a = core::ptr::addr_of!(p) as u32;

    // Mask and offset to get stack use
    // (this is ~100 bytes larger than computed, probably due to _start or vector table)
    let s = 30720 - (a & 0xFFFF);

    // Set context for a syscall, allows this to be printed under speculos
    unsafe {
        nanos_sdk::bindings::try_context_set(s as *mut try_context_s);
    }
}
