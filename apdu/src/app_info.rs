// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Application Information APDUs

use encdec::{Decode, DecodeOwned, Encode};

use super::{ApduError, ApduStatic, Instruction, MOB_APDU_CLA};

/// Fetch application info APDU
#[derive(Copy, Clone, PartialEq, Debug, Default)]
pub struct AppInfoReq {}

impl ApduStatic for AppInfoReq {
    /// Application Info command APDU is class `0xb0`
    const CLA: u8 = MOB_APDU_CLA;

    /// Application Info GET APDU is instruction `0x00`
    const INS: u8 = Instruction::GetAppInfo as u8;
}

impl Encode for AppInfoReq {
    type Error = ApduError;

    fn encode_len(&self) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn encode(&self, _buff: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }
}

impl DecodeOwned for AppInfoReq {
    type Output = Self;

    type Error = ApduError;

    fn decode_owned(_buff: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        Ok((Self {}, 0))
    }
}

/// Application information response APDU
///
/// ## Encoding
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   PROTO_VER   |   NAME_LEN    |  VERSION_LEN  |   FLAGS_LEN   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                             NAME...                           /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                            VERSION...                         /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                             FLAGS...                          /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct AppInfoResp<'a> {
    /// Protocol version (must be 1)
    pub proto: u8,

    /// Application name
    pub name: &'a str,

    /// Application version
    pub version: &'a str,

    /// Application flags
    pub flags: AppFlags,
}

bitflags::bitflags! {
    /// Application info flags
    pub struct AppFlags: u16 {
        /// Indicates app is unlocked for key requests
        const UNLOCKED = 1 << 0;

        /// Indicates app has tx summary feature
        const HAS_TX_SUMMARY = 1 << 8;
    }
}

impl<'a> AppInfoResp<'a> {
    /// Create a new application version APDU
    pub fn new(proto: u8, name: &'a str, version: &'a str, flags: AppFlags) -> Self {
        Self {
            proto,
            name,
            version,
            flags,
        }
    }
}

impl<'a> Encode for AppInfoResp<'a> {
    type Error = ApduError;

    /// Encode an app version APDU into the provided buffer
    fn encode(&self, buff: &mut [u8]) -> Result<usize, ApduError> {
        let mut index = 0;

        // TODO: check buffer length is viable

        // Set header
        buff[0] = self.proto;
        buff[1] = self.name.len() as u8;
        buff[2] = self.version.len() as u8;
        buff[3] = self.flags.encode_len()? as u8;
        index += 4;

        // Write name
        buff[index..][..self.name.len()].copy_from_slice(self.name.as_bytes());
        index += self.name.len();

        // Write version
        buff[index..][..self.version.len()].copy_from_slice(self.version.as_bytes());
        index += self.version.len();

        // Write flags
        index += self.flags.encode(&mut buff[index..])?;

        Ok(index)
    }

    /// Compute APDU encoded length
    fn encode_len(&self) -> Result<usize, ApduError> {
        let mut len = 4;

        len += self.name.len();
        len += self.version.len();
        len += self.flags.encode_len()?;

        Ok(len)
    }
}

impl<'a> Decode<'a> for AppInfoResp<'a> {
    type Output = Self;
    type Error = ApduError;

    /// Decode an app version APDU from the provided buffer
    fn decode(buff: &'a [u8]) -> Result<(Self, usize), ApduError> {
        let mut index = 0;

        // TODO: check buffer length

        // Fetch headers
        let proto = buff[0];
        let name_len = buff[1] as usize;
        let version_len = buff[2] as usize;
        let flags_len = buff[3] as usize;
        index += 4;

        // Fetch name string
        let name = core::str::from_utf8(&buff[index..][..name_len]).map_err(|_| ApduError::Utf8)?;
        index += name_len;

        // Fetch version string
        let version =
            core::str::from_utf8(&buff[index..][..version_len]).map_err(|_| ApduError::Utf8)?;
        index += version_len;

        // Fetch flags
        let (flags, n) = AppFlags::decode_owned(&buff[index..][..flags_len])?;
        index += n;

        Ok((
            Self {
                proto,
                name,
                version,
                flags,
            },
            index,
        ))
    }
}

impl Encode for AppFlags {
    type Error = ApduError;

    fn encode_len(&self) -> Result<usize, Self::Error> {
        Ok(3)
    }

    fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
        // Check buffer size
        if buff.len() < 3 {
            return Err(ApduError::InvalidLength);
        }

        // Set flags length
        buff[0] = 2;

        // Write actual flags
        let b = self.bits().to_le_bytes();
        buff[1..][..2].copy_from_slice(&b);

        // Return length
        Ok(3)
    }
}

impl DecodeOwned for AppFlags {
    type Output = Self;

    type Error = ApduError;

    fn decode_owned(buff: &[u8]) -> Result<(Self::Output, usize), Self::Error> {
        // Check buffer size
        if buff.len() < 2 {
            return Err(ApduError::InvalidLength);
        }

        // Check flags length matches
        let len = buff[0];
        if len != 2 {
            return Err(ApduError::InvalidEncoding);
        }

        // Decode flags
        let bits = u16::from_le_bytes([buff[1], buff[2]]);
        let flags = AppFlags::from_bits_truncate(bits);

        // Return decoded flags and length
        Ok((flags, 3))
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::test::encode_decode_apdu;

    #[test]
    fn app_info_req_apdu() {
        let apdu = AppInfoReq::default();

        let mut buff = [0u8; 128];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn app_info_resp_apdu() {
        let name = "TEST NAME";
        let version = "TEST VERSION";

        let apdu = AppInfoResp::new(1, name, version, AppFlags::UNLOCKED);

        let mut buff = [0u8; 128];
        encode_decode_apdu(&mut buff, &apdu);
    }
}
