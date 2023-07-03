// Copyright (c) 2022-2023 The MobileCoin Foundation

/// [Engine] errors
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
#[repr(u8)]
pub enum Error {
    /// Invalid argument length
    #[cfg_attr(feature = "thiserror", error("Invalid argument length"))]
    InvalidLength = 0x00,

    /// Unexpected event
    #[cfg_attr(feature = "thiserror", error("Unexpected event"))]
    UnexpectedEvent = 0x01,

    /// Too many ring entries
    #[cfg_attr(feature = "thiserror", error("Too many ring entries"))]
    RingFull = 0x02,

    /// Signing error
    #[cfg_attr(feature = "thiserror", error("Signing error"))]
    SignError = 0x03,

    /// Missing blinding values
    #[cfg_attr(feature = "thiserror", error("blinding values missing"))]
    MissingBlindings = 0x04,

    /// Invalid key (decompression failed)
    #[cfg_attr(feature = "thiserror", error("invalid ristretto key"))]
    InvalidKey = 0x05,

    /// Missing onetime_private_key
    #[cfg_attr(feature = "thiserror", error("onetime_private_key missing"))]
    MissingOnetimePrivateKey = 0x06,

    /// Error when deriving keys for signing
    #[cfg_attr(feature = "thiserror", error("failed to recover onetime_private_key"))]
    OnetimeKeyRecoveryFailed = 0x07,

    /// Error configuring ring for signing
    #[cfg_attr(feature = "thiserror", error("failed to start ring signing"))]
    RingInitFailed = 0x08,

    /// Error updating ring
    #[cfg_attr(feature = "thiserror", error("failed to update ring"))]
    RingUpdateFailed = 0x09,

    /// Invalid engine state
    #[cfg_attr(feature = "thiserror", error("invalid engine state"))]
    InvalidState = 0x0a,

    /// Message encoding failed
    #[cfg_attr(feature = "thiserror", error("message encoding failed"))]
    EncodingFailed = 0x0b,

    /// Pending user approval
    #[cfg_attr(feature = "thiserror", error("pending user approval"))]
    ApprovalPending = 0x0c,

    /// Summary initialisation failed
    #[cfg_attr(feature = "thiserror", error("failed to start summary computation"))]
    SummaryInitFailed = 0x0d,

    /// Summary missing output
    #[cfg_attr(feature = "thiserror", error("missing summary output"))]
    SummaryMissingOutput = 0x0e,

    /// Summary initialisation failed
    #[cfg_attr(feature = "thiserror", error("identity request rejected"))]
    IdentRejected = 0x0f,

    /// Unknown / not-yet defined error (placeholder)
    #[cfg_attr(feature = "thiserror", error("unknown"))]
    Unknown = 0xf0,
}
