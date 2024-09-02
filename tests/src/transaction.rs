// Copyright (c) 2022-2023 The MobileCoin Foundation

use std::{sync::Arc, time::Duration};

use bip39::Mnemonic;

use ledger_lib::Device;
use rand_core::OsRng;
use std::future::Future;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace};

use mc_core::{
    account::{Account, PublicSubaddress},
    consts::CHANGE_SUBADDRESS_INDEX,
    slip10::Slip10KeyGenerator,
    subaddress::Subaddress,
};
use mc_transaction_core::tx::Tx;
use mc_transaction_core::validation::validate_signature;
use mc_transaction_signer::types::{TxSignReq, TxSignResp};
use mc_transaction_summary::verify_tx_summary;

use ledger_mob::{
    tx::{TransactionHandle, TxConfig},
    DeviceHandle,
};

pub struct TransactionExpectation<'a> {
    pub mnemonic: &'a str,
    pub request: &'a str,
}

impl<'a> TransactionExpectation<'a> {
    pub fn mnemonic(&self) -> Mnemonic {
        Mnemonic::from_phrase(self.mnemonic, bip39::Language::English).unwrap()
    }

    pub fn account(&self) -> Account {
        let s = self.mnemonic().derive_slip10_key(0);
        Account::from(&s)
    }

    pub fn tx_req(&self) -> TxSignReq {
        serde_json::from_str(self.request).unwrap()
    }
}

pub const TRANSACTIONS: &[TransactionExpectation<'static>] = &[
    TransactionExpectation {
        mnemonic: "duck deal pretty pen thunder economy wide common goose fit engine main aisle curtain choose cube claim snake enroll detect brief history float unit",
        request: include_str!("../vectors/tx1.json"),
    }, TransactionExpectation {
        mnemonic:"cinnamon gas finger morning fault bean autumn whip envelope foam endless also forest avoid cigar paper mirror royal crime wolf birth vacant foster color",
        request: include_str!("../vectors/tx2.json"),
    }, TransactionExpectation {
        mnemonic: "duck deal pretty pen thunder economy wide common goose fit engine main aisle curtain choose cube claim snake enroll detect brief history float unit",
        request: include_str!("../vectors/tx3.json"),
    }, TransactionExpectation {
        mnemonic: "duck deal pretty pen thunder economy wide common goose fit engine main aisle curtain choose cube claim snake enroll detect brief history float unit",
        request: include_str!("../vectors/tx4.json"),
    },
];

struct HexFmt<T: AsRef<[u8]>>(pub T);

impl<T: AsRef<[u8]>> core::fmt::Display for HexFmt<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0.as_ref() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

pub async fn test<'a, T, F>(
    t: T,
    approve: impl Fn() -> F,
    tx: &TransactionExpectation<'a>,
) -> anyhow::Result<()>
where
    T: Device + Send,
    F: Future<Output = ()>,
{
    // Load account and unsigned transaction
    let account = tx.account();
    let change = account.subaddress(CHANGE_SUBADDRESS_INDEX);
    let req = tx.tx_req();

    trace!("Request: {:?}", req);

    // Setup device handle
    let d = DeviceHandle::from(t);

    info!("Starting transaction");

    // Initialise transaction
    let mut signer = TransactionHandle::new(
        TxConfig {
            account_index: 0,
            num_memos: 0,
            num_rings: req.rings.len(),
            request_timeout: Duration::from_millis(500),
            user_timeout: Duration::from_secs(3),
        },
        Arc::new(Mutex::new(d)),
    )
    .await?;

    // Build the digest for ring signing
    debug!("Fetching signing data");
    let (signing_data, summary, unblinding, digest) = req.get_signing_data(&mut OsRng {}).unwrap();

    // Set the message or compute summary depending on block version
    // TODO: is block version the right switch for this..?

    error!(
        "Using extended digest: {:02x?}",
        signing_data.mlsag_signing_digest
    );

    match unblinding {
        None => {
            debug!("Setting tx message");
            signer.set_message(&digest.0).await?;
        }
        Some(unblinding) => {
            debug!("Loading tx summary");
            signer
                .set_tx_summary(req.block_version, &digest.0, &summary, &unblinding)
                .await?;

            // TODO: check signing_data matches computed mlsag_signing_digest
            let mut m = [0u8; 32];
            m.copy_from_slice(&digest.0[..]);

            let (expected_digest, _report) = verify_tx_summary(
                &m,
                &summary,
                &unblinding,
                account.view_private_key().clone().inner(),
                PublicSubaddress::from(&change),
            )
            .unwrap();

            assert_eq!(
                &expected_digest[..],
                &signing_data.mlsag_signing_digest[..],
                "summary generated digest mismatch"
            );
        }
    }

    // Trigger approver function
    approve().await;

    // Await user input
    debug!("Waiting for user confirmation");
    signer.await_approval(20).await?;

    // Execute signing (signs rings etc.)
    debug!("Executing signing operation");
    let signature = signing_data
        .sign(&req.rings, &signer, &mut OsRng {})
        .map_err(|e| anyhow::anyhow!("Ring signing error: {:?}", e))?;

    debug!("Signing complete");

    // Build sign response
    let resp = TxSignResp {
        account_id: req.account_id,
        tx: Tx {
            prefix: req.tx_prefix.clone(),
            signature,
            fee_map_digest: vec![],
        },
        // TODO: fill / check these
        txos: vec![],
    };

    trace!("Response: {:?}", resp);

    // Signal transaction is complete
    signer.complete().await?;

    info!("Transaction complete! validating signature");

    // Validate generated transaction signature
    validate_signature(req.block_version, &resp.tx, &mut OsRng {}).unwrap();

    Ok(())
}
