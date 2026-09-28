//! Schrnorrkel / fog authority signing helpers
//!
//! These implement the same behaviour as the upstream `Signer` and `Verifier`
//! traits, with modifications to reduce stack use for execution on the ledger.
//!

use mc_core::keys::SubaddressViewPrivate;
use mc_crypto_digestible::MerlinTranscript;
use mc_crypto_keys::{RistrettoPrivate, RistrettoSignature};

use core::mem::MaybeUninit;

use rand_core::block::BlockRng;
use rand_hc::Hc128Core;
use schnorrkel_og::{context::attach_rng, SecretKey as SchnorrkelPrivate};

// Create a deterministic nonce using a merlin transcript. See this crate's
// README for a security statement.
#[inline(never)]
fn schnorrkel_nonce(private_key: &RistrettoPrivate, context: &[u8], message: &[u8]) -> [u8; 32] {
    let mut transcript = MerlinTranscript::new(b"SigningNonce");
    transcript.append_message(b"context", context);
    transcript.append_message(b"private", private_key.as_ref());
    transcript.append_message(b"message", message);
    let mut nonce = [0u8; 32];
    transcript.challenge_bytes(b"nonce", &mut nonce);
    nonce
}

// Construct a Schnorrkel SecretKey object from ourselves, and our nonce value
#[inline(never)]
fn schnorrkel_secret(private_key: &RistrettoPrivate, nonce: &[u8; 32]) -> SchnorrkelPrivate {
    let mut secret_bytes = [0u8; 64];
    secret_bytes[0..32].copy_from_slice(private_key.as_ref());
    secret_bytes[32..64].copy_from_slice(&nonce[..]);
    SchnorrkelPrivate::from_bytes(&secret_bytes).unwrap()
}

#[inline(never)]
fn schnorrkel_sign(
    private_key: &RistrettoPrivate,
    context: &[u8],
    message: &[u8],
) -> RistrettoSignature {
    // Create a deterministic nonce using a merlin transcript. See this crate's
    // README for a security statement.
    let nonce = schnorrkel_nonce(private_key, context, message);

    // Construct a Schnorrkel SecretKey object from ourselves, and our nonce value
    let secret_key = schnorrkel_secret(private_key, &nonce);
    let keypair = secret_key.to_keypair();

    // SigningContext provides domain separation for signature
    let mut t = MerlinTranscript::new(b"SigningContext");
    t.append_message(b"", context);
    t.append_message(b"sign-bytes", message);
    // NOTE: This signature is deterministic due to using the above nonce as the rng
    // seed

    // Setup HC128 RNG core.
    //
    // NOTE: initialised in place. The state is 4100 bytes and `from_seed`
    // returns it by value, which LLVM leaves as two live stack copies joined
    // by a memcpy -- 8200 bytes, more than the nanox has stack (MOB-XX).
    // `BlockRng` then drives it by reference so it is not moved again.
    let mut state = MaybeUninit::uninit();
    let core = Hc128Core::from_seed_in_place(&mut state, &nonce);
    let mut csprng = BlockRng::new(core);

    let mut transcript = attach_rng(t, &mut csprng);
    RistrettoSignature::from(keypair.sign(&mut transcript))
}

/// Canonical signing context byte string
const CONTEXT: &[u8] = b"Fog authority signature";

/// Re-implementation of `Signer` for `RistrettoPrivate` using reference types
/// to minimize stack allocations
#[inline(never)]
pub fn sign_authority(
    private_key: &SubaddressViewPrivate,
    spki_bytes: &[u8],
) -> RistrettoSignature {
    schnorrkel_sign(private_key.as_ref(), CONTEXT, spki_bytes)
}

#[cfg(test)]
mod test {
    use mc_account_keys::{AccountKey, DEFAULT_SUBADDRESS_INDEX};
    use mc_crypto_keys::RistrettoPublic;
    use mc_fog_sig_authority::{Signer, Verifier};
    use mc_util_from_random::FromRandom;
    use rand_core::OsRng;

    use ledger_mob_apdu::tx::FogId;

    use super::*;
    use crate::engine::FogCert;

    const FOGS: &[FogId] = &[
        FogId::MobMain,
        FogId::MobTest,
        FogId::SignalMain,
        FogId::SignalTest,
    ];

    #[test]
    fn schnorrkel_sign_verify() {
        for _i in 0..10 {
            let k = RistrettoPrivate::from_random(&mut OsRng {});
            let p = RistrettoPublic::from(&k);
            let spki = FogId::MobMain.spki();

            // Generate using upstream impl
            let s1 = k.sign_authority(spki).unwrap();
            p.verify_authority(spki, &s1).unwrap();

            // Generate using local impl
            let s2 = sign_authority(&k.into(), spki);
            p.verify_authority(spki, &s2).unwrap();

            // Check impls match
            assert_eq!(s1, s2);
        }
    }

    #[test]
    fn fog_authority_sigs() {
        for f in FOGS {
            for _i in 0..10 {
                // Create random account with fog info
                let spki = f.spki();
                let a = AccountKey::random(&mut OsRng {}).with_fog(f.url(), "", spki);

                // Using the default subaddress
                let subaddr = a.subaddress(DEFAULT_SUBADDRESS_INDEX);
                let view_private = a.default_subaddress_view_private();

                // Generate authority signature using local impl
                let sig: [u8; 64] = sign_authority(&view_private.into(), spki).into();

                // Verify authority signature
                subaddr
                    .view_public_key()
                    .verify_authority(spki, &RistrettoSignature::try_from(&sig[..]).unwrap())
                    .unwrap();

                // Check local impl matches upstream
                assert_eq!(
                    sig,
                    subaddr.fog_authority_sig().unwrap(),
                    "Fog authority signature mismatch"
                );
            }
        }
    }
}
