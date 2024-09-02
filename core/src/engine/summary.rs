#![allow(unused)]
// Copyright (c) 2022-2023 The MobileCoin Foundation

use alloc::string::ToString;
use heapless::Vec;

use ledger_mob_apdu::tx::FogId;
use strum::{Display, EnumIter, EnumString, EnumVariantNames};

use mc_core::{
    account::{PublicSubaddress, ShortAddressHash},
    keys::{RootViewPrivate, SubaddressViewPublic, TxOutPublic, TxOutTargetPublic},
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

use crate::{apdu::tx::TxPrivateKey, helpers::digest_public_address};

use super::{Error, Event};

/// Wrapper for streaming tx summaries
pub struct Summarizer<const MAX_RECORDS: usize = 16> {
    state: SummaryState,
    verifier: Option<TxSummaryStreamingVerifierCtx>,
    report: TxSummaryUnblindingReport<MAX_RECORDS>,
    addresses: Vec<OutputAddress, MAX_RECORDS>,
    tx_out_summary: Option<TxOutSummary>,
    num_outputs: usize,
    num_inputs: usize,
}

/// Summarizer state enumeration
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

/// Cached output address for later rendering
pub struct OutputAddress {
    /// Short address hash, matched against report entries
    pub short_hash: ShortAddressHash,
    /// Public address
    pub address: PublicSubaddress,
    /// Fog information
    pub fog_id: FogId,
    /// Fog signature
    pub fog_sig: Option<[u8; 64]>,
}

impl<const MAX_RECORDS: usize> Summarizer<MAX_RECORDS> {
    /// Create a new summarizer instance
    pub fn new(
        message: &[u8; 32],
        block_version: BlockVersion,
        num_outputs: usize,
        num_inputs: usize,
        view_private_key: &RootViewPrivate,
        change_address: &PublicSubaddress,
    ) -> Result<Self, Error> {
        // Check we have some inputs / outputs
        if num_inputs == 0 || num_outputs == 0 {
            return Err(Error::SummaryInitFailed);
        }

        // Setup verifier
        let verifier = Some(TxSummaryStreamingVerifierCtx::new(
            message,
            block_version,
            num_outputs,
            num_inputs,
            view_private_key.clone().inner(),
            change_address.clone(),
        ));

        let report = TxSummaryUnblindingReport::default();

        Ok(Self {
            state: SummaryState::Init,
            verifier,
            report,
            addresses: Vec::new(),
            tx_out_summary: None,
            num_outputs,
            num_inputs,
        })
    }

    /// out-pointer based init to avoid stack allocation
    /// see: https://doc.rust-lang.org/core/mem/union.MaybeUninit.html#out-pointers
    // TODO: per-field init might improve headroom _if_ we continue to require this
    #[cfg_attr(feature = "noinline", inline(never))]
    pub unsafe fn init(
        p: *mut Self,
        message: &[u8; 32],
        block_version: BlockVersion,
        num_outputs: usize,
        num_inputs: usize,
        view_private_key: &RootViewPrivate,
        change_address: &PublicSubaddress,
    ) -> Result<(), Error> {
        // Check we have some inputs / outputs (MOB-06.3)
        if num_inputs == 0 || num_outputs == 0 {
            return Err(Error::SummaryInitFailed);
        }

        p.write(Self {
            state: SummaryState::Init,
            verifier: Some(TxSummaryStreamingVerifierCtx::new(
                message,
                block_version,
                num_outputs,
                num_inputs,
                view_private_key.clone().inner(),
                change_address.clone(),
            )),
            report: TxSummaryUnblindingReport::default(),
            addresses: Vec::new(),
            tx_out_summary: None,
            num_outputs,
            num_inputs,
        });

        Ok(())
    }

    /// Add output information to the summary (must be followed by `add_output_unblinding`)
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn add_output_summary(
        &mut self,
        masked_amount: Option<&MaskedAmount>,
        target_key: &CompressedRistrettoPublic,
        public_key: &CompressedRistrettoPublic,
        associated_to_input_rules: bool,
    ) -> Result<SummaryState, Error> {
        // Build txout summary
        let tx_out_summary = TxOutSummary {
            masked_amount: masked_amount.cloned(),
            target_key: *target_key,
            public_key: *public_key,
            associated_to_input_rules,
        };

        // Cache summary for next `add_output_unblinding` call.
        self.tx_out_summary = Some(tx_out_summary);

        // Update state
        self.state = match self.state {
            SummaryState::Init => SummaryState::AddTxOut(0),
            // Increment only occurs from `add_output_unblinding`
            SummaryState::AddTxOut(n) => SummaryState::AddTxOut(n),
            _ => return Err(Error::InvalidState),
        };

        Ok(self.state)
    }

    /// Add output unblinding to the summary (must follow `add_output_summary`)
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn add_output_unblinding(
        &mut self,
        unmasked_amount: &UnmaskedAmount,
        address: Option<&PublicSubaddress>,
        fog_info: Option<(FogId, &[u8; 64])>,
        tx_private_key: Option<&TxPrivateKey>,
    ) -> Result<SummaryState, Error> {
        // Check state
        match self.state {
            SummaryState::AddTxOut(_) => (),
            _ => return Err(Error::InvalidState),
        }

        // Fetch summary from prior step (and fail if this doesn't exist)
        let tx_out_summary = match self.tx_out_summary.take() {
            Some(v) => v,
            None => {
                #[cfg(feature = "log")]
                log::error!("add_output_unblinding missing output for unblinding");

                return Err(Error::SummaryMissingOutput);
            }
        };

        let verifier = match &mut self.verifier {
            Some(v) => v,
            None => {
                #[cfg(feature = "log")]
                log::error!("add_output_unblinding missing verifier");

                return Err(Error::InvalidState);
            }
        };

        // Regenerate short hash for address
        let (fog_url, fog_sig) = fog_info
            .map(|(f, s)| (f.url(), &s[..]))
            .unwrap_or(("", &[]));
        let a = address.map(|a| (digest_public_address(a, fog_url, fog_sig), a));

        // Cache output address' for future display
        if let Some((h, _)) = &a {
            if !self.addresses.iter().any(|v| &v.short_hash == h) {
                self.addresses.push(OutputAddress {
                    short_hash: *h,
                    address: address.cloned().unwrap(),
                    fog_id: fog_info.map(|(f, _)| f).unwrap_or_default(),
                    fog_sig: fog_info.map(|(_, s)| *s),
                });
            }
        }

        // Digest output w/ unblinding info
        match verifier.digest_output(
            &tx_out_summary,
            unmasked_amount,
            a,
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
            // When we've added all outputs, swap to `AddTxIn` state (MOB-06.3)
            SummaryState::AddTxOut(n) if n + 1 == self.num_outputs => SummaryState::AddTxIn(0),
            // Otherwise keep counting inputs
            SummaryState::AddTxOut(n) => SummaryState::AddTxOut(n + 1),
            _ => return Err(Error::InvalidState),
        };

        Ok(self.state)
    }

    #[cfg_attr(feature = "noinline", inline(never))]
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
            // When we've added all inputs swap to `Ready` state
            SummaryState::AddTxIn(n) if n + 1 == self.num_inputs => SummaryState::Ready,
            // Otherwise keep counting inputs
            SummaryState::AddTxIn(n) => SummaryState::AddTxIn(n + 1),
            _ => return Err(Error::InvalidState),
        };

        Ok(self.state)
    }

    #[cfg_attr(feature = "noinline", inline(never))]
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

        // Elide SCIs from totals for rendering
        // TODO: we may wish to revisit this when SCIs are widely used
        self.report.elide_swap_totals();

        // Set complete state
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

    /// Fetch address from summarizer cache (must be called after `finalize`)
    #[inline]
    pub fn address(&self, h: &ShortAddressHash) -> Option<&OutputAddress> {
        self.addresses.iter().find(|v| &v.short_hash == h)
    }
}

#[cfg(test)]
mod test {
    use core::mem::MaybeUninit;
    use core::str::FromStr;

    use log::*;
    use mc_core::consts::CHANGE_SUBADDRESS_INDEX;
    use mc_core::{account::Account, keys::Key, subaddress::Subaddress};
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
        #[cfg(feature = "log")]
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
            &account.subaddress(CHANGE_SUBADDRESS_INDEX),
        )
        .unwrap();

        assert_eq!(
            &expected_digest[..],
            &signing_data.mlsag_signing_digest[..],
            "summary generated digest mismatch"
        );

        // Setup summarizer
        let mut s = MaybeUninit::<Summarizer<16>>::uninit();
        let mut s = unsafe {
            Summarizer::<16>::init(
                s.as_mut_ptr(),
                &extended_message_digest,
                req.block_version,
                summary.outputs.len(),
                summary.inputs.len(),
                account.view_private_key(),
                &PublicSubaddress::from(&account.subaddress(CHANGE_SUBADDRESS_INDEX)),
            )
            .unwrap();
            s.assume_init()
        };

        let progress_total = summary.inputs.len() + summary.outputs.len() + 1;

        // Write outputs
        for i in 0..summary.outputs.len() {
            let summary = &summary.outputs[i];
            let unblinding = &unblinding_data.outputs[i];

            s.add_output_summary(
                summary.masked_amount.as_ref(),
                &summary.target_key,
                &summary.public_key,
                summary.associated_to_input_rules,
            )
            .unwrap();

            let address = unblinding.address.as_ref();
            let k = unblinding.tx_private_key.map(Key::from);

            let fog_info =
                address.and_then(|a| match (a.fog_report_url(), a.fog_authority_sig()) {
                    (Some(url), Some(s)) => {
                        let fog_id = FogId::from_str(url).unwrap();

                        let mut sig = [0u8; 64];
                        sig.copy_from_slice(s.as_ref());
                        Some((fog_id, sig))
                    }
                    _ => None,
                });

            s.add_output_unblinding(
                &unblinding.unmasked_amount,
                address.map(PublicSubaddress::from).as_ref(),
                fog_info.as_ref().map(|(f, s)| (*f, s)),
                k.as_ref(),
            )
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
        assert!(s < 8192, "summarizer size: {s} > 8192");
    }
}
