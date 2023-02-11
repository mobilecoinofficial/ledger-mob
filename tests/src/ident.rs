// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Tests and vectors for ed25519 identity operations
//!
//!

use std::future::Future;

use bip39::{Language, Mnemonic, Seed};
use ed25519_dalek::{PublicKey, Signature};
use ledger_transport::Exchange;

use ledger_mob_apdu::{
    ident::{IdentGetReq, IdentResp, IdentSignReq},
    state::TxState,
    tx::{TxInfo, TxInfoReq},
};

/// Test vector type for identity derivation and challenge signing
pub struct Vector {
    pub mnemonic: &'static str,
    pub uri: &'static str,
    pub index: u32,
    pub path: [u32; 5],
    pub public_key: &'static str,
}

impl Vector {
    pub fn seed(&self) -> [u8; 64] {
        let m = Mnemonic::from_phrase(self.mnemonic, Language::English).unwrap();
        let seed = Seed::new(&m, "");

        let mut b = [0u8; 64];
        b.copy_from_slice(seed.as_bytes());

        b
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        hex::decode_to_slice(self.public_key, &mut b[..]).unwrap();
        b
    }
}

pub const VECTORS: &[Vector] = &[
    Vector{
        mnemonic: "mirror stamp work suffer now tilt demand eagle love repair country poem exhaust output conduct panic kidney wide able clown zebra rural moon wrist",
        uri: "ssh://holtzman@media.mit.edu",
        index: 0,
        path: [2147483661, 2972399321, 3374192999, 3573283404, 2507362653],
        public_key: "3a177abf1b8721988cf0298bd97f3c99ae8a14a6161995f361012d214bdd30fa"
    },
    Vector{
        mnemonic: "mirror stamp work suffer now tilt demand eagle love repair country poem exhaust output conduct panic kidney wide able clown zebra rural moon wrist",
        uri: "ssh://one",
        index: 0,
        path: [2147483661, 3464129099, 2889699098, 2670538080, 2865375321],
        public_key: "fbbeea2187d4dfb7817de11fb228831d2e782c4be6c1dc39ef0ea597588a74ec"
    },
    Vector{
        mnemonic: "pudding sausage permit foil zero response legend dash buffalo infant blame trust race render ask uncover motor pull system build grant window negative theory",
        uri: "ssh://henry@mobilecoin.com",
        index: 0,
        path: [2147483661, 2424855808, 3126637913, 4097351350, 2177034064],
        public_key: "7a2b1aa4afe890f550a1e6d80d2a833dd712765795a20acd4da7ebddfce7aec3"
    },
    Vector{
        mnemonic: "pudding sausage permit foil zero response legend dash buffalo infant blame trust race render ask uncover motor pull system build grant window negative theory",
        uri: "ssh://two",
        index: 0,
        path: [2147483661, 2382642382, 2395115496, 3978206390, 3287685313],
        public_key: "43d0fec962902973b24e84516eb4c2b5c2f0aba5c58f2ac3c01d8dc6dbda5b6d"
    },
];

/// Test identity requests
pub async fn test<T, F, E>(t: T, approve: impl Fn() -> F, v: &Vector) -> anyhow::Result<()>
where
    T: Exchange<Error = E>,
    F: Future<Output = ()>,
    E: std::error::Error + Sync + Send + 'static,
{
    let mut buff = [0u8; 256];

    // Issue identity request
    let challenge: [u8; 32] = rand::random();
    let req = IdentSignReq::new(v.index, v.uri, &challenge);

    let resp = t.exchange::<TxInfo>(req, &mut buff).await.unwrap();

    // Check pending state
    assert_eq!(resp.state, TxState::IdentPending, "expected ident pending");

    // Execute approver
    approve().await;

    // Check approval state
    let resp = t.exchange::<TxInfo>(TxInfoReq, &mut buff).await.unwrap();
    assert_eq!(
        resp.state,
        TxState::IdentApproved,
        "expected ident approved"
    );

    // Fetch identity response
    let resp = t
        .exchange::<IdentResp>(IdentGetReq, &mut buff)
        .await
        .unwrap();

    // Check response public key matches expectation
    assert_eq!(
        resp.public_key,
        v.public_key_bytes(),
        "public key derivation mismatch"
    );

    // Check challenge signature
    let public_key = PublicKey::from_bytes(&resp.public_key).unwrap();
    public_key
        .verify_strict(&challenge, &Signature::from(resp.signature))
        .unwrap();

    Ok(())
}
