
use core::mem::MaybeUninit;

use mc_core::keys::SubaddressViewPrivate;
use mc_crypto_digestible::MerlinTranscript;
use mc_crypto_keys::{RistrettoPrivate, RistrettoSignature};

use rand_core::{block::{BlockRng, BlockRngCore}, SeedableRng, CryptoRngCore};
use rand_hc::Hc128Core;
use schnorrkel_og::{SecretKey as SchnorrkelPrivate, context::attach_rng};

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
pub fn schnorrkel_sign(private_key: &RistrettoPrivate, context: &[u8], message: &[u8]) -> RistrettoSignature {
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

    // Setup HC128 RNG core
    let mut core = Hc128Core::from_seed(nonce);

    // Wrap this in BlockRng
    // using a pointer container to avoid further allocation
    let container = Hc128CoreContainer(&mut core);
    let mut csprng = BlockRng::new(container);

    //let mut csprng = Hc128Rng::from_seed(nonce);
    let mut transcript = attach_rng(t, &mut csprng);
    RistrettoSignature::from(keypair.sign(&mut transcript))
}

/// Wrapper for [Hc128Core] pointer, working around the lack of 
/// a blanket [BlockRngCore] impl for `&mut T` where `T: BlockRngCore`.
struct Hc128CoreContainer<'a>(&'a mut Hc128Core);

impl <'a>BlockRngCore for Hc128CoreContainer<'a> {
    type Item = u32;
    type Results = [u32; 16];

    fn generate(&mut self, results: &mut Self::Results) {
        self.0.generate(results);
    }
}

impl <'a> rand_core::CryptoRng for Hc128CoreContainer<'a> {}

/// Canonical signing context byte string
const CONTEXT: &'static [u8] = b"Fog authority signature";

/// Re-implementation of `Signer` for `RistrettoPrivate` using types to minimize allocations
#[inline(never)]
pub fn sign_authority(private_key: &SubaddressViewPrivate, spki_bytes: &[u8]) -> RistrettoSignature {
    schnorrkel_sign(private_key.as_ref(), CONTEXT, spki_bytes)
}

#[cfg(test)]
mod test {

}
