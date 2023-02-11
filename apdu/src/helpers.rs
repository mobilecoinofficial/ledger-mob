#![allow(unused)]
// Copyright (c) 2022-2023 The MobileCoin Foundation

/// encdec helper module for scalars
pub(crate) mod scalar {
    use ledger_apdu::ApduError;
    use mc_crypto_ring_signature::Scalar;

    pub fn enc(s: &Scalar, buff: &mut [u8]) -> Result<usize, ApduError> {
        let d = s.to_bytes();

        if buff.len() < d.len() {
            return Err(ApduError::InvalidLength);
        }

        buff[..d.len()].copy_from_slice(&d);

        Ok(d.len())
    }

    pub fn enc_len(_s: &Scalar) -> Result<usize, ApduError> {
        Ok(32)
    }

    pub fn dec(buff: &[u8]) -> Result<(Scalar, usize), ApduError> {
        let mut d = [0u8; 32];

        if buff.len() < d.len() {
            return Err(ApduError::InvalidLength);
        }

        d.copy_from_slice(&buff[..32]);

        let s = Scalar::from_bytes_mod_order(d);

        Ok((s, d.len()))
    }
}

/// encdec helper module for public keys
pub(crate) mod pub_key {
    use ledger_apdu::ApduError;

    use mc_crypto_keys::RistrettoPublic;

    pub fn enc<K: AsRef<RistrettoPublic>>(k: K, buff: &mut [u8]) -> Result<usize, ApduError> {
        let d = k.as_ref().to_bytes();

        if buff.len() < d.len() {
            return Err(ApduError::InvalidLength);
        }

        buff[..d.len()].copy_from_slice(&d);

        Ok(d.len())
    }

    pub fn enc_len<K: AsRef<RistrettoPublic>>(k: &K) -> Result<usize, ApduError> {
        let d = k.as_ref().to_bytes();
        Ok(d.len())
    }

    pub fn dec<K: From<RistrettoPublic>>(buff: &[u8]) -> Result<(K, usize), ApduError> {
        let mut d = [0u8; 32];

        if buff.len() < d.len() {
            return Err(ApduError::InvalidLength);
        }

        d.copy_from_slice(&buff[..32]);

        let k = match RistrettoPublic::try_from(&d) {
            Ok(v) => v,
            Err(_) => return Err(ApduError::InvalidEncoding),
        };

        Ok((K::from(k), 32))
    }
}

/// encdec helper module for private keys

pub(crate) mod pri_key {
    use ledger_apdu::ApduError;

    use mc_crypto_keys::RistrettoPrivate;

    pub fn enc<K: AsRef<RistrettoPrivate>>(k: K, buff: &mut [u8]) -> Result<usize, ApduError> {
        let d = k.as_ref().to_bytes();

        if buff.len() < d.len() {
            return Err(ApduError::InvalidLength);
        }

        buff[..d.len()].copy_from_slice(&d);

        Ok(d.len())
    }

    pub fn enc_len<K: AsRef<RistrettoPrivate>>(k: &K) -> Result<usize, ApduError> {
        let d = k.as_ref().to_bytes();
        Ok(d.len())
    }

    pub fn dec<K: From<RistrettoPrivate>>(buff: &[u8]) -> Result<(K, usize), ApduError> {
        let mut d = [0u8; 32];

        if buff.len() < d.len() {
            return Err(ApduError::InvalidLength);
        }

        d.copy_from_slice(&buff[..32]);

        let k = match RistrettoPrivate::try_from(&d) {
            Ok(v) => v,
            Err(_) => return Err(ApduError::InvalidEncoding),
        };

        Ok((K::from(k), 32))
    }
}

/// encdec helper module for compressed points
pub(crate) mod pt {
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use ledger_apdu::ApduError;
    use mc_crypto_keys::CompressedRistrettoPublic;

    pub fn enc<P: AsRef<[u8; 32]>>(p: P, buff: &mut [u8]) -> Result<usize, ApduError> {
        let d: &[u8; 32] = p.as_ref();

        if buff.len() < d.len() {
            return Err(ApduError::InvalidLength);
        }

        buff[..d.len()].copy_from_slice(&d[..]);

        Ok(d.len())
    }

    pub fn enc_len<P: AsRef<[u8; 32]>>(p: P) -> Result<usize, ApduError> {
        Ok(32)
    }

    pub fn dec<P: From<CompressedRistretto>>(buff: &[u8]) -> Result<(P, usize), ApduError> {
        let mut d = [0u8; 32];

        if buff.len() < d.len() {
            return Err(ApduError::InvalidLength);
        }

        d.copy_from_slice(&buff[..32]);

        let c = CompressedRistretto::from_slice(&d);
        let p = P::from(c);

        Ok((p, 32))
    }
}

/// encdec helper module for key images
pub(crate) mod ki {
    use ledger_apdu::ApduError;
    use mc_crypto_ring_signature::KeyImage;

    pub fn enc(p: &KeyImage, buff: &mut [u8]) -> Result<usize, ApduError> {
        let d = p.as_bytes();

        if buff.len() < d.len() {
            return Err(ApduError::InvalidLength);
        }

        buff[..d.len()].copy_from_slice(&d[..]);

        Ok(d.len())
    }

    pub fn enc_len(p: &KeyImage) -> Result<usize, ApduError> {
        let d = p.as_bytes();
        Ok(d.len())
    }

    pub fn dec(buff: &[u8]) -> Result<(KeyImage, usize), ApduError> {
        if buff.len() < 32 {
            return Err(ApduError::InvalidLength);
        }

        let p = match KeyImage::try_from(&buff[..32]) {
            Ok(v) => v,
            Err(_) => return Err(ApduError::InvalidEncoding),
        };

        Ok((p, 32))
    }
}

/// Encoding helper for `kind` field (pending nightly array constructors)
pub(crate) mod arr {
    use encdec::Error;

    pub fn enc<const N: usize>(d: &[u8; N], buff: &mut [u8]) -> Result<usize, Error> {
        if buff.len() < d.len() {
            return Err(Error::Length);
        }

        buff[..d.len()].copy_from_slice(&d[..]);

        Ok(d.len())
    }

    pub fn enc_len<const N: usize>(d: &[u8; N]) -> Result<usize, Error> {
        Ok(d.len())
    }

    pub fn dec<const N: usize>(buff: &[u8]) -> Result<([u8; N], usize), Error> {
        if buff.len() < N {
            return Err(Error::Length);
        }

        let mut d = [0u8; N];
        d.copy_from_slice(&buff[..N]);

        Ok((d, N))
    }
}
