// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Transaction related APDUs, used to execute a transaction via the hardware wallet.
//!
//! See [ledger_mob_core::engine] for interaction and state machines

use encdec::{Decode, Encode};
use ledger_proto::ApduStatic;

use crate::{
    state::{Digest, TxState},
    ApduError, Instruction, MOB_APDU_CLA,
};

mod tx_init;
pub use tx_init::*;

mod ring;
pub use ring::*;

mod memo;
pub use memo::*;

mod summary;
pub use summary::*;

/// Transaction information request APDU
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxInfoReq;

impl ApduStatic for TxInfoReq {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxGetInfo as u8;
}

/// Complete transaction operation (0 length APDU)
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]

pub struct TxComplete;

impl ApduStatic for TxComplete {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::TxComplete as u8;
}

/// Transaction information response APDU.
///
/// Received in response to TX commands, contains the current transaction engine state, a value where relevant (ie. ring index when streaming rings), and a digest over operations in the transaction to mitigate state errors.
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            TX_STATE           |             VALUE             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           TX_DIGEST                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxInfo {
    /// Current transaction engine state
    pub state: TxState,
    /// Value associated with current state (zero otherwise)
    pub value: u16,
    /// Transaction state digest
    pub digest: Digest,
}

/// Header shared between TX response APDUs
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            TX_STATE           |             VALUE             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                           TX_DIGEST                           |
/// |                    32-byte rolling checksum                   |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct TxHeader {
    /// Current transaction engine state
    pub state: TxState,
    /// Value associated with current state (zero otherwise)
    pub value: u16,
    /// Transaction state digest
    pub digest: Digest,
}

#[cfg(test)]
mod test {
    // TODO: test encode / decode
}
