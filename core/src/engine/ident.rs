// Copyright (c) 2022-2023 The MobileCoin Foundation
use core::str::FromStr;

use heapless::{String, Vec};

use byteorder::{ByteOrder, LittleEndian};
use mc_core::slip10::Slip10Key;
use sha2::{Digest, Sha256};
use strum::{EnumIter, EnumString};

use super::{Error, Output};

/// Identity challenge state
#[derive(Copy, Clone, Debug, PartialEq, Default, EnumString, EnumIter)]
pub enum IdentState {
    /// Challenge loaded, pending approval
    #[default]
    Pending,
    /// Challenge approved, signing allowed
    Approved,
    /// Challenged rejected, return error
    Denied,
}

/// Identity challenge signing module
pub struct Ident {
    /// SLIP-0017 account index (note this differs from SLIP-0010)
    pub identity_index: u32,
    /// Identity URI
    pub identity_uri: String<64>,
    /// Challenge to be signed
    pub challenge: Vec<u8, 64>,
}

impl Ident {
    /// Create a new ident context
    pub fn new(identity_index: u32, uri: &str, challenge: &[u8]) -> Result<Self, Error> {
        let identity_uri = String::from_str(uri).map_err(|_| Error::InvalidLength)?;
        let challenge = Vec::try_from(challenge).map_err(|_| Error::InvalidLength)?;

        Ok(Self {
            identity_index,
            identity_uri,
            challenge,
        })
    }

    pub fn uri(&self) -> &str {
        &self.identity_uri
    }

    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    /// Compute path for identity key derivation
    pub fn path(&self) -> [u32; 5] {
        derive_bip32(&self.identity_uri, self.identity_index)
    }

    /// Compute identity challenge signature using the provide private key
    pub fn compute(&self, private_key: &Slip10Key) -> Output {
        #[cfg(feature = "log")]
        log::debug!("computing identity proof");

        // Convert to public key type
        let keys = ed25519_dalek::SigningKey::try_from(private_key.as_ref()).unwrap();
        let signature = ed25519_dalek::Signer::sign(&keys, &self.challenge);
        let verifying_key = keys.verifying_key();

        // Force drop and zeroize of private keys (MOB-01.1)
        drop(keys);

        Output::Identity {
            public_key: verifying_key.to_bytes(),
            signature: signature.to_bytes(),
        }
    }
}

/// SLIP-0013 path derivation
///
/// https://github.com/satoshilabs/slips/blob/master/slip-0013.md
pub(crate) fn derive_bip32(uri: &str, index: u32) -> [u32; 5] {
    // Build URI/index hash
    let mut hasher = Sha256::new();

    // TODO: when they say concatentate, do they mean via -string-?
    hasher.update(index.to_le_bytes());
    hasher.update(uri.as_bytes());

    let r = hasher.finalize();
    let b = r.as_slice();

    // Setup derivation path
    let mut p = [0u32; 5];
    p[0] = 13 | (1 << 31);
    for i in 0..4 {
        p[i + 1] = LittleEndian::read_u32(&b[i * 4..]) | (1 << 31);
    }

    p
}

#[cfg(test)]
mod test {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use super::derive_bip32;
    use ledger_mob_tests::ident::{Vector, VECTORS};

    #[test]
    fn slip0013_derive_path() {
        for Vector {
            uri, index, path, ..
        } in VECTORS
        {
            let p = derive_bip32(uri, *index);
            assert_eq!(&p, path, "derivation path mismatch");
        }
    }

    #[test]
    fn slip0013_derive_full() {
        for v in VECTORS {
            // Derive seed from mnemonic
            let seed = v.seed();

            // Generate path
            let p = derive_bip32(v.uri, v.index);
            assert_eq!(&p, &v.path, "derivation path mismatch");

            // Derive private key
            let secret_key = slip10_ed25519::derive_ed25519_private_key(&seed, &p);

            // Compute public key
            let secret_key = SigningKey::from_bytes(&secret_key);
            let public_key = VerifyingKey::from(&secret_key);

            // Compare with expectations
            assert_eq!(public_key.as_bytes(), &v.public_key_bytes());
        }
    }
}
