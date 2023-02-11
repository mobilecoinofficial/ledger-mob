// Copyright (c) 2022-2023 The MobileCoin Foundation

use heapless::{String, Vec};

use byteorder::{ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use strum::{EnumIter, EnumString};

use super::{Error, Output};

/// Identity challenge state
#[derive(Copy, Clone, Debug, PartialEq, Default, EnumString, EnumIter)]
pub enum IdentState {
    #[default]
    Pending,
    Approved,
    Denied,
    Error,
}

impl IdentState {
    pub fn is_pending(&self) -> bool {
        *self == IdentState::Pending
    }
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
        let identity_uri = String::try_from(uri).map_err(|_| Error::InvalidLength)?;
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
    pub fn compute(&self, private_key: &[u8]) -> Result<Output, Error> {
        #[cfg(feature = "log")]
        log::debug!("computing identity proof");

        // Convert to public key type
        let private_key = ed25519_dalek::SecretKey::from_bytes(private_key).unwrap();
        let public_key = ed25519_dalek::PublicKey::from(&private_key);

        // Sign provided challenge
        let keys = ed25519_dalek::Keypair {
            public: public_key,
            secret: private_key,
        };
        let signature = ed25519_dalek::Signer::sign(&keys, &self.challenge);

        Ok(Output::Identity {
            public_key: keys.public.to_bytes(),
            signature: signature.to_bytes(),
        })
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
    use ed25519_dalek::{PublicKey, SecretKey};

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
            let secret_key = SecretKey::from_bytes(&secret_key).unwrap();
            let public_key = PublicKey::from(&secret_key);

            // Compare with expectations
            assert_eq!(public_key.as_bytes(), &v.public_key_bytes());
        }
    }
}
