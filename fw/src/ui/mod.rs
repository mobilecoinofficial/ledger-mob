//! User interface (modules|components) for Ledger devices.

#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
pub mod nano;

#[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
pub mod touch;
