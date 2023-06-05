#![allow(unused)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bip39::Seed;
use ledger_proto::{ApduBase, ApduReq};
use log::{debug, trace};

use ledger_mob_core::engine::{Driver, Engine, Error, Event};

pub const MNEMONIC: &str = "duck deal pretty pen thunder economy wide common goose fit engine main aisle curtain choose cube claim snake enroll detect brief history float unit";

#[derive(Clone)]
pub struct TestEngine {
    pub engine: Arc<Mutex<Engine<TestDriver>>>,
}

impl TestEngine {
    pub fn new(engine: Engine<TestDriver>) -> Self {
        Self {
            engine: Arc::new(Mutex::new(engine)),
        }
    }

    pub fn unlock(&self) {
        let mut e = self.engine.lock().unwrap();
        e.unlock();
    }

    pub fn approve_ident(&self, approve: bool) {
        let mut e = self.engine.lock().unwrap();
        e.ident_approve(approve);
    }
}

#[async_trait]
impl ledger_lib::Device for TestEngine {
    async fn request<'a, 'b, RESP: ApduBase<'b>>(
        &mut self,
        request: impl ApduReq<'a> + Send,
        buff: &'b mut [u8],
        timeout: Duration,
    ) -> Result<RESP, ledger_lib::Error> {
        let h = request.header();

        debug!("cmd: {:?}", request);

        // Encode command to APDU (skipping header)
        let n = request.encode(buff).unwrap();

        assert!(
            n < 250,
            "encoded command maximum length exceeded for: {request:?} ({n} bytes)"
        );

        trace!("encoded: {:02x?}", &buff[..n]);

        // Decode APDU to event
        let evt = match Event::parse(h.ins, &buff[..n]) {
            Ok(v) => v,
            Err(e) => {
                panic!("Decode failed with {:?} for: {:02x?}", e, &buff[..n]);
            }
        };

        // Handle event
        let mut engine = self.engine.lock().unwrap();
        let r = engine.update(&evt).unwrap();

        // Encode output to response APDU
        let n = r.encode(buff).unwrap();

        assert!(
            n < 250,
            "encoded response maximum length exceeded for: {r:?} ({n} bytes)"
        );

        // Decode response APDU
        let (a, _) = RESP::decode(&buff[..n]).unwrap();

        debug!("resp: {:?}", a);

        // Return response APDU
        Ok(a)
    }
}

/// Driver implementation for test use
pub struct TestDriver {
    /// BIP39 Mnemonic derived seed
    pub seed: [u8; 64],
}

impl TestDriver {
    pub fn new(seed: Seed) -> Self {
        let mut b = [0u8; 64];
        b.copy_from_slice(seed.as_bytes());
        Self { seed: b }
    }
}

impl Driver for TestDriver {
    fn slip10_derive_ed25519(&self, path: &[u32]) -> [u8; 32] {
        slip10_ed25519::derive_ed25519_private_key(&self.seed, path)
    }
}

pub async fn approve_tx(e: &TestEngine) {
    debug!("Approve transaction");

    let mut e = e.engine.lock().unwrap();
    e.approve();
}

pub async fn unlock(e: &TestEngine) {
    debug!("Unlock engine");

    let mut e = e.engine.lock().unwrap();
    e.unlock();
}

pub async fn approve_ident(e: &TestEngine) {
    debug!("Approve ident");

    let mut e = e.engine.lock().unwrap();
    e.ident_approve(true);
}
