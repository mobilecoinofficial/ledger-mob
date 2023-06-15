// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ledger MobileCoin Platform Support

use core::{ffi::CStr, mem::MaybeUninit};

use encdec::Encode;

use ledger_proto::{apdus::DeviceInfoResp, ApduError};
use nanos_sdk::{
    bindings::{os_perso_derive_node_with_seed_key, HDW_ED25519_SLIP10},
    ecc,
    uxapp::UxEvent,
};
#[cfg(feature = "nvm")]
use nanos_sdk::{
    nvm::{AtomicStorage, SingleStorage},
    Pic,
};

use ledger_mob_core::{apdu::tx::FogId, engine::Driver};

#[cfg(feature = "nvm")]
use ledger_mob_core::apdu::tx::FOG_IDS;

/// Fog ID for address display
/// Note NVM is not available under speculos so accessing this page will fault.
#[cfg(feature = "nvm")]
#[cfg_attr(feature = "nvm", link_section = ".nvm_data")]
static mut FOG: Pic<AtomicStorage<u32>> = Pic::new(AtomicStorage::new(&(FogId::MobMain as u32)));

#[cfg(not(feature = "nvm"))]
static mut FOG: MaybeUninit<FogId> = MaybeUninit::uninit();

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

/// Fetch fog ID from platform persistent storage
#[cfg(feature = "nvm")]
pub fn platform_get_fog_id() -> FogId {
    let i = unsafe { *FOG.get_ref().get_ref() } as usize;
    if i < FOG_IDS.len() {
        FOG_IDS[i]
    } else {
        FogId::MobMain
    }
}

/// Update fog ID in platform persistent storage
#[cfg(feature = "nvm")]
pub fn platform_set_fog_id(fog_id: &FogId) {
    unsafe {
        let f = FOG.get_mut();
        f.update(&(*fog_id as u32));
    };
}

// `nvm` feature gate exists due to fault with nvm under
// speculos _and_ currently on hw

/// Fetch fog ID from local variable
#[cfg(not(feature = "nvm"))]
pub fn platform_get_fog_id() -> FogId {
    unsafe { FOG.assume_init() }
}

/// Update fog ID in local variable
#[cfg(not(feature = "nvm"))]
pub fn platform_set_fog_id(fog_id: &FogId) {
    unsafe { FOG.write(*fog_id) };
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

/// Blocking request for pin validation to unlock
pub fn request_pin_validation() {
    UxEvent::ValidatePIN.request();
}

pub fn fetch_encode_device_info(buff: &mut [u8]) -> Result<usize, ApduError> {
    // Fetch information from OS
    let mut mcu_version_raw = [0u8; 32];
    let mut se_version_raw = [0u8; 32];
    let flags;
    unsafe {
        flags = nanos_sdk::bindings::os_flags();
        nanos_sdk::bindings::os_version(mcu_version_raw.as_mut_ptr(), se_version_raw.len() as u32);
        nanos_sdk::bindings::os_seph_version(
            se_version_raw.as_mut_ptr(),
            se_version_raw.len() as u32,
        );
    }

    // Convert to rust strings
    let mcu_version = match CStr::from_bytes_until_nul(&mcu_version_raw).map(|c| c.to_str()) {
        Ok(Ok(v)) => v,
        _ => "unknown",
    };
    let se_version = match CStr::from_bytes_until_nul(&se_version_raw).map(|c| c.to_str()) {
        Ok(Ok(v)) => v,
        _ => "unknown",
    };
    let f = flags.to_be_bytes();

    // Select target information
    #[cfg(target_os = "nanosplus")]
    let target_id: u32 = 0x33100004;
    #[cfg(target_os = "nanox")]
    let target_id: u32 = 0x33000004;

    // Build DeviceInfo APDU
    let r = DeviceInfoResp::new(target_id.to_be_bytes(), se_version, mcu_version, &f);

    // Encode APDU to buffer
    r.encode(buff)
}
