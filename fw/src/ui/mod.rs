//! User interface (modules|components) for Ledger devices.

#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
pub mod nano;

#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
pub mod touch;
