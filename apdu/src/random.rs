// Copyright (c) 2022-2023 The MobileCoin Foundation

use encdec::{Decode, Encode};

use super::{ApduError, ApduStatic, Instruction, MOB_APDU_CLA};
use crate::helpers::arr;

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct RandomReq {}

impl ApduStatic for RandomReq {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::GetRandom as u8;
}

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct RandomResp {
    /// Random value
    #[encdec(with = "arr")]
    pub value: [u8; 32],
}
