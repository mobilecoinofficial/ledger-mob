// Copyright (c) 2022-2023 The MobileCoin Foundation

use base64::prelude::{Engine as _, BASE64_STANDARD};

#[derive(Clone, PartialEq, Debug)]
pub struct HexData<const N: usize = 32>(pub [u8; N]);

impl<const N: usize> std::str::FromStr for HexData<N> {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut b = [0u8; N];

        hex::decode_to_slice(s, &mut b)?;

        Ok(HexData(b))
    }
}

impl<const N: usize> AsRef<[u8; N]> for HexData<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> std::string::ToString for HexData<N> {
    fn to_string(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct B64Data<const N: usize = 32>(pub [u8; N]);

impl<const N: usize> std::str::FromStr for B64Data<N> {
    type Err = base64::DecodeSliceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut b = [0u8; N];

        BASE64_STANDARD.decode_slice(s, &mut b)?;

        Ok(B64Data(b))
    }
}
