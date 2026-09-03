//! User interface (modules|components) for Ledger devices. 

#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
pub mod nano;

#[cfg(any(target_os = "stax"))]
pub mod ngbl;
