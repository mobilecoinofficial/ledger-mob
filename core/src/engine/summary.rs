#![allow(unused)]
// Copyright (c) 2022-2023 The MobileCoin Foundation

use strum::{Display, EnumIter, EnumString, EnumVariantNames};

use mc_core::{
    account::{PublicSubaddress, ShortAddressHash},
    keys::{RootViewPrivate, TxOutPublic, TxOutTargetPublic},
};
use mc_crypto_digestible::{DigestTranscript, Digestible};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_crypto_ring_signature::CompressedCommitment;

use mc_transaction_summary::{
    TransactionEntity, TxSummaryStreamingVerifierCtx, TxSummaryUnblindingReport,
};
use mc_transaction_types::{
    Amount, BlockVersion, MaskedAmount, TxInSummary, TxOutSummary, UnmaskedAmount,
};

use crate::apdu::tx::TxPrivateKey;

use super::{Error, Event};

/// Wrapper for streaming tx summaries
pub struct Summarizer<const MAX_RECORDS: usize = 16> {
    state: SummaryState,
    verifier: Option<TxSummaryStreamingVerifierCtx>,
    report: TxSummaryUnblindingReport<MAX_RECORDS>,
    tx_out_summary: Option<TxOutSummary>,
    num_outputs: usize,
    num_inputs: usize,
}

/// [Summarizer] state enumeration
#[derive(
    Copy, Clone, PartialEq, Debug, Default, EnumString, Display, EnumVariantNames, EnumIter,
)]
pub enum SummaryState {
    #[default]
    Init,
    AddTxIn(usize),
    AddTxOut(usize),
    Ready,
    Complete,
}

impl<const MAX_RECORDS: usize> Summarizer<MAX_RECORDS> {
    /// Create a new summarizer instance
    pub fn new(
        message: &[u8],
        block_version: BlockVersion,
        num_outputs: usize,
        num_inputs: usize,
        view_private_key: &RootViewPrivate,
    ) -> Self {
        // TODO: check message length

        // Setup verifier
        let verifier = Some(TxSummaryStreamingVerifierCtx::new(
            message,
            block_version,
            num_outputs,
            num_inputs,
            view_private_key.clone().inner(),
        ));

        let report = TxSummaryUnblindingReport::default();

        Self {
            state: SummaryState::Init,
            verifier,
            report,
            tx_out_summary: None,
            num_outputs,
            num_inputs,
        }
    }

    /// out-pointer based init to avoid stack allocation
    /// see: https://doc.rust-lang.org/core/mem/union.MaybeUninit.html#out-pointers
    pub unsafe fn init(
        p: *mut Self,
        message: &[u8],
        block_version: BlockVersion,
        num_outputs: usize,
        num_inputs: usize,
        view_private_key: &RootViewPrivate,
    ) {
        p.write(Self {
            state: SummaryState::Init,
            verifier: Some(TxSummaryStreamingVerifierCtx::new(
                message,
                block_version,
                num_outputs,
                num_inputs,
                view_private_key.clone().inner(),
            )),
            report: TxSummaryUnblindingReport::default(),
            tx_out_summary: None,
            num_outputs,
            num_inputs,
        })
    }

    /// Add output information to the summary (must be followed by `add_output_unblinding`)
    pub fn add_output_summary(
        &mut self,
        masked_amount: Option<MaskedAmount>,
        target_key: &CompressedRistrettoPublic,
        public_key: &CompressedRistrettoPublic,
        associated_to_input_rules: bool,
    ) -> Result<SummaryState, Error> {
        // Build txout summary
        let tx_out_summary = TxOutSummary {
            masked_amount,
            target_key: *target_key,
            public_key: *public_key,
            associated_to_input_rules,
        };

        // Attach for next computation
        self.tx_out_summary = Some(tx_out_summary);

        // Update state
        self.state = match self.state {
            SummaryState::Init => SummaryState::AddTxOut(0),
            SummaryState::AddTxOut(n) => SummaryState::AddTxOut(n),
            _ => return Err(Error::InvalidState),
        };

        Ok(self.state)
    }

    /// Add output unblinding to the summary (must follow `add_output_summary`)
    pub fn add_output_unblinding(
        &mut self,
        unmasked_amount: &UnmaskedAmount,
        address: Option<(ShortAddressHash, PublicSubaddress)>,
        tx_private_key: Option<TxPrivateKey>,
    ) -> Result<SummaryState, Error> {
        // TODO: check state

        // Fetch summary from prior step
        let tx_out_summary = match self.tx_out_summary.take() {
            Some(v) => v,
            None => {
                #[cfg(feature = "log")]
                log::error!("add_output_unblinding missing output for unblinding");

                return Err(Error::UnexpectedEvent);
            }
        };

        let verifier = match &mut self.verifier {
            Some(v) => v,
            None => {
                #[cfg(feature = "log")]
                log::error!("add_output_unblinding missing verifier");

                return Err(Error::UnexpectedEvent);
            }
        };

        // Digest output w/ unblinding info
        match verifier.digest_output(
            &tx_out_summary,
            unmasked_amount,
            address,
            tx_private_key.as_ref().map(|v| v.as_ref()),
            &mut self.report,
        ) {
            Ok(_) => (),
            Err(e) => {
                #[cfg(feature = "log")]
                log::error!("add_output_unblinding failed: {:?}", e);

                return Err(Error::Unknown);
            }
        }

        // Update state
        self.state = match self.state {
            SummaryState::AddTxOut(n) if n >= self.num_outputs - 1 => SummaryState::AddTxIn(0),
            SummaryState::AddTxOut(n) => SummaryState::AddTxOut(n + 1),
            _ => return Err(Error::InvalidState),
        };

        Ok(self.state)
    }

    pub fn add_input(
        &mut self,
        pseudo_output_commitment: CompressedCommitment,
        input_rules_digest: Option<[u8; 32]>,
        unmasked_amount: &UnmaskedAmount,
    ) -> Result<SummaryState, Error> {
        // TODO: check state

        let input_rules_digest = match input_rules_digest {
            Some(v) => v.to_vec(),
            None => [].to_vec(),
        };

        // Build txin summary
        let tx_in_summary = TxInSummary {
            pseudo_output_commitment,
            input_rules_digest,
        };

        let verifier = match &mut self.verifier {
            Some(v) => v,
            None => {
                #[cfg(feature = "log")]
                log::error!("add_input missing verifier");

                return Err(Error::UnexpectedEvent);
            }
        };

        // Digest input
        match verifier.digest_input(&tx_in_summary, unmasked_amount, &mut self.report) {
            Ok(_) => (),
            Err(e) => {
                #[cfg(feature = "log")]
                log::error!("add_input failed: {:?}", e);

                return Err(Error::Unknown);
            }
        }

        // Update state
        self.state = match self.state {
            SummaryState::AddTxIn(n) if n >= self.num_inputs - 1 => SummaryState::Ready,
            SummaryState::AddTxIn(n) => SummaryState::AddTxIn(n + 1),
            _ => return Err(Error::InvalidState),
        };

        Ok(self.state)
    }

    pub fn finalize(
        &mut self,
        fee: Amount,
        tombstone_block: u64,
        digest: &mut [u8; 32],
    ) -> Result<SummaryState, Error> {
        // TODO: check state

        let verifier = match self.verifier.take() {
            Some(v) => v,
            None => {
                #[cfg(feature = "log")]
                log::error!("finalize missing verifier");

                return Err(Error::UnexpectedEvent);
            }
        };

        // Finalise verification report
        verifier.finalize(fee, tombstone_block, digest, &mut self.report);

        self.state = SummaryState::Complete;

        // Return message and report
        Ok(self.state)
    }

    /// Fetch Summarizer state
    #[inline]
    pub fn state(&self) -> SummaryState {
        self.state
    }

    /// Fetch summarizer progress (n / 100)
    pub fn progress(&self) -> usize {
        let total = self.num_inputs + self.num_outputs + 1;

        #[cfg(feature = "log")]
        log::debug!("progress: {:?} / {}", self.state, total);

        let index = match self.state {
            SummaryState::Init => 0,
            SummaryState::AddTxOut(n) => n,
            SummaryState::AddTxIn(n) => self.num_outputs + n,
            SummaryState::Ready => self.num_outputs + self.num_inputs,
            SummaryState::Complete => self.num_outputs + self.num_inputs + 1,
        };

        index * 100 / total
    }

    /// Fetch report from summarizer (must be called after `finalize`)
    #[inline]
    pub fn report(&self) -> &TxSummaryUnblindingReport<MAX_RECORDS> {
        &self.report
    }

    /// Wrapper to handle summary update events
    pub fn update(&mut self, evt: &Event) -> Result<SummaryState, Error> {
        match evt {
            Event::TxSummaryAddOutput {
                masked_amount,
                target_key,
                public_key,
                associated_to_input_rules,
            } => self.add_output_summary(
                masked_amount.clone(),
                target_key,
                public_key,
                *associated_to_input_rules,
            ),
            Event::TxSummaryAddOutputUnblinding {
                unmasked_amount,
                address,
                tx_private_key,
            } => {
                self.add_output_unblinding(unmasked_amount, address.clone(), tx_private_key.clone())
            }
            Event::TxSummaryAddInput {
                pseudo_output_commitment,
                input_rules_digest,
                unmasked_amount,
            } => self.add_input(
                *pseudo_output_commitment,
                *input_rules_digest,
                unmasked_amount,
            ),

            _ => Err(Error::UnexpectedEvent),
        }
    }
}

#[cfg(test)]
mod test {
    use log::*;
    use mc_core::{account::Account, keys::Key};
    use mc_transaction_summary::verify_tx_summary;
    use rand_core::OsRng;

    use ledger_mob_tests::transaction::{test, TRANSACTIONS};

    use super::*;

    #[test]
    fn tx_summary() {
        let _ = simplelog::TermLogger::init(
            log::LevelFilter::Debug,
            Default::default(),
            simplelog::TerminalMode::Mixed,
            simplelog::ColorChoice::Auto,
        );

        // Load transaction and account info
        let account = TRANSACTIONS[2].account();
        let req = TRANSACTIONS[2].tx_req();

        // Fetch signing information
        debug!("Fetching signing data");
        let (signing_data, summary, unblinding, digest) =
            req.get_signing_data(&mut OsRng {}).unwrap();

        let unblinding_data = unblinding.unwrap();
        let mut extended_message_digest = [0u8; 32];
        extended_message_digest.copy_from_slice(&digest.0[..]);

        // Check signing_data matches computed mlsag_signing_digest
        let (expected_digest, report) = verify_tx_summary(
            &extended_message_digest,
            &summary,
            &unblinding_data,
            account.view_private_key().clone().inner(),
        )
        .unwrap();

        assert_eq!(
            &expected_digest[..],
            &signing_data.mlsag_signing_digest[..],
            "summary generated digest mismatch"
        );

        // Run summariser
        let mut s = Summarizer::<16>::new(
            &extended_message_digest,
            req.block_version,
            summary.outputs.len(),
            summary.inputs.len(),
            account.view_private_key(),
        );

        let progress_total = summary.inputs.len() + summary.outputs.len() + 1;

        // Write outputs
        for i in 0..summary.outputs.len() {
            let summary = &summary.outputs[i];
            let unblinding = &unblinding_data.outputs[i];

            s.add_output_summary(
                summary.masked_amount.clone(),
                &summary.target_key,
                &summary.public_key,
                summary.associated_to_input_rules,
            )
            .unwrap();

            let a = unblinding
                .address
                .as_ref()
                .map(|a| (ShortAddressHash::from(a), PublicSubaddress::from(a)));
            let k = unblinding.tx_private_key.map(Key::from);

            s.add_output_unblinding(&unblinding.unmasked_amount, a, k)
                .unwrap();

            let progress = s.progress();
            assert_eq!(
                progress,
                (i + 1) * 100 / progress_total,
                "progress mismatch for output: {i} (/{progress_total})"
            );
        }

        // Write inputs
        for i in 0..summary.inputs.len() {
            let input_summary = &summary.inputs[i];
            let unblinding = &unblinding_data.inputs[i];

            let input_rules_digest = match input_summary.input_rules_digest.len() {
                0 => None,
                32 => {
                    let mut b = [0u8; 32];
                    b.copy_from_slice(&input_summary.input_rules_digest[..]);
                    Some(b)
                }
                _ => panic!("invalid input rules digest length"),
            };

            s.add_input(
                input_summary.pseudo_output_commitment,
                input_rules_digest,
                &UnmaskedAmount {
                    value: unblinding.value,
                    token_id: unblinding.token_id,
                    blinding: unblinding.blinding,
                },
            )
            .unwrap();

            let progress = s.progress();
            assert_eq!(
                progress,
                (i + summary.outputs.len() + 1) * 100 / progress_total,
                "progress mismatch for output: {i} (/{progress_total})"
            );
        }

        // Complete summary
        let mut computed_digest = [0u8; 32];
        let _report = s
            .finalize(
                Amount {
                    value: summary.fee,
                    token_id: summary.fee_token_id.into(),
                },
                summary.tombstone_block,
                &mut computed_digest,
            )
            .unwrap();

        let progress = s.progress();
        assert_eq!(progress, 100);

        // TODO: check report

        assert_eq!(
            &computed_digest[..],
            &expected_digest[..],
            "Summarizer generated incorrect digest?!"
        );
    }

    #[test]
    fn summarizer_size() {
        // TODO: check summarizer size is reasonable
        let s = core::mem::size_of::<Summarizer<16>>();
        assert!(s < 2048, "summarizer size: {s}");
    }
}
