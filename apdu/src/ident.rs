// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Ed25519 Identity APDUs for SLIP-0013/17 signing support

use encdec::{Decode, Encode};

use super::{ApduError, ApduStatic, Instruction, MOB_APDU_CLA};
use crate::helpers::arr;

/// Request an ed25519 identity for provided URI and index,
/// returning a state object.
///
/// See [IdentGetReq] for fetching the identity and challenge following
/// user approval.
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       IDENTITY_INDEX                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  IDENTITY_LEN | CHALLENGE_LEN |           RESERVED            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                         IDENTITY_URI                          /
/// /                       (variable length)                       /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                          CHALLLENGE                           /
/// /                       (variable length)                       /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, PartialEq, Debug)]
pub struct IdentSignReq<'a> {
    /// SLIP-0017 account index (note this differs from SLIP-0010)
    pub identity_index: u32,
    /// Identity URI
    pub identity_uri: &'a str,
    /// Challenge to be signed
    pub challenge: &'a [u8],
}

impl<'a> IdentSignReq<'a> {
    /// Create a new application version APDU
    pub fn new(identity_index: u32, identity_uri: &'a str, challenge: &'a [u8]) -> Self {
        Self {
            identity_index,
            identity_uri,
            challenge,
        }
    }
}

impl<'a> ApduStatic for IdentSignReq<'a> {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::IdentSignReq as u8;
}

impl<'a> Encode for IdentSignReq<'a> {
    type Error = ApduError;

    /// Encode an [`IdentReq`] APDU into the provided buffer
    #[inline]
    fn encode(&self, buff: &mut [u8]) -> Result<usize, ApduError> {
        let mut index = 0;
        let d = self.identity_uri.as_bytes();

        // Check buffer length is valid
        if buff.len() < d.len() + self.challenge.len() + 8 {
            return Err(ApduError::InvalidLength);
        }

        // Write identity index
        index += self.identity_index.encode(&mut buff[index..])?;

        // Write uri length (and padding)
        buff[index] = d.len() as u8;
        index += 1;

        // Write challenge length
        buff[index] = self.challenge.len() as u8;
        index += 1;

        // Write padding
        index += 2;

        // Write uri
        buff[index..][..d.len()].copy_from_slice(d);
        index += d.len();

        // Write challenge
        buff[index..][..self.challenge.len()].copy_from_slice(self.challenge);
        index += self.challenge.len();

        Ok(index)
    }

    #[inline]
    fn encode_len(&self) -> Result<usize, ApduError> {
        Ok(8 + self.identity_uri.as_bytes().len() + self.challenge.len())
    }
}

impl<'a> Decode<'a> for IdentSignReq<'a> {
    type Output = Self;
    type Error = ApduError;

    /// Decode a [`IdentReq`] APDU from the provided buffer
    #[inline]
    fn decode(buff: &'a [u8]) -> Result<(Self, usize), ApduError> {
        let mut index = 0;

        // Check header length (MOB-06.8)
        if buff.len() < 8 {
            return Err(ApduError::InvalidLength);
        }

        // Read identity index
        let (identity_index, n) = u32::decode(&buff[index..])?;
        index += n;

        // Read identity URI length
        let uri_len = buff[index] as usize;
        index += 1;

        // Read challenge length
        let challenge_len = buff[index] as usize;
        index += 1;

        // Skip padding
        index += 2;

        // Check full buffer length (MOB-06.8)
        if buff.len() < 8 + uri_len + challenge_len {
            return Err(ApduError::InvalidLength);
        }

        // Read identity URI
        let identity_uri =
            core::str::from_utf8(&buff[index..][..uri_len]).map_err(|_| ApduError::InvalidUtf8)?;
        index += uri_len;

        let challenge = &buff[index..][..challenge_len];
        index += challenge_len;

        Ok((
            Self {
                identity_index,
                identity_uri,
                challenge,
            },
            index,
        ))
    }
}

/// Fetch an identity object from the device following user approval
/// returns [`IdentResp`] APDU.
#[derive(Copy, Clone, Debug, PartialEq, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct IdentGetReq;

impl ApduStatic for IdentGetReq {
    const CLA: u8 = MOB_APDU_CLA;
    const INS: u8 = Instruction::IdentGetReq as u8;
}

/// Identity key response APDU, contains derived ed25519 public key
///
/// ## Encoding:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                          PUBLIC_KEY                           /
/// /                  (32-byte ed25519 public key)                 /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                            SIGNATURE                          /
/// /                   (64-byte ed25519 signature)                 /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Copy, Clone, PartialEq, Debug, Encode, Decode)]
#[encdec(error = "ApduError")]
pub struct IdentResp {
    /// Derived public key
    #[encdec(with = "arr")]
    pub public_key: [u8; 32],
    /// Signature over challenge
    #[encdec(with = "arr")]
    pub signature: [u8; 64],
}

impl IdentResp {
    /// Create a new [`KeyImage`] APDU
    pub fn new(public_key: [u8; 32], signature: [u8; 64]) -> Self {
        Self {
            public_key,
            signature,
        }
    }
}

#[cfg(test)]
mod test {
    use rand::random;

    use super::*;
    use crate::test::encode_decode_apdu;

    #[test]
    fn identity_key_req_apdu() {
        let apdu = IdentSignReq::new(
            random(),
            "ssh://someone@something.com:2222",
            &[1, 2, 3, 4, 5, 6],
        );

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }

    #[test]
    fn identity_key_resp_apdu() {
        let mut sig = [0u8; 64];
        for b in sig.iter_mut() {
            *b = random();
        }

        let apdu = IdentResp::new(random(), sig);

        let mut buff = [0u8; 256];
        encode_decode_apdu(&mut buff, &apdu);
    }
}
