// Copyright (c) 2022-2023 The MobileCoin Foundation

use log::warn;
use std::ops::Deref;

use ledger_lib::Device;

use mc_core::account::ShortAddressHash;
use mc_transaction_core::{BlockVersion, TxSummary};
use mc_transaction_summary::TxSummaryUnblindingData;

use ledger_mob_apdu::{state::TxState, tx::*};

use super::{check_state, TransactionHandle};
use crate::Error;

impl<T: Device + Send> TransactionHandle<T> {
    /// Load tx summary for signing operation, alternative to `set_message` for block versions > 3
    pub async fn set_tx_summary(
        &mut self,
        block_version: BlockVersion,
        message: &[u8],
        summary: &TxSummary,
        unblinding: &TxSummaryUnblindingData,
    ) -> Result<(), Error> {
        let mut buff = [0u8; 256];

        warn!("Loading TX summary");

        //let (expected_digest, report) = verify_tx_summary(message, summary, unblinding_data, view_private_key);

        // Setup summary state
        let mut m = [0u8; 32];
        m[..message.len()].copy_from_slice(message);

        let init = TxSummaryInit {
            message: m,
            block_version: *block_version.deref(),
            num_inputs: summary.inputs.len() as u32,
            num_outputs: summary.outputs.len() as u32,
        };
        let resp = self
            .request::<TxInfo>(init, &mut buff, self.info.request_timeout)
            .await?;

        // Check state and expected digest
        check_state(resp.state, TxState::SummaryInit)?;
        //check_digest::<T>(&resp.digest, &ctx.digest)?;

        warn!("Write {} TxOuts", summary.outputs.len());

        // Write outputs to summary
        if summary.outputs.len() != unblinding.outputs.len() {
            // TODO: what should be here..?
        }

        for n in 0..summary.outputs.len() {
            let o = &summary.outputs[n];
            let u = &unblinding.outputs[n];

            // Build tx out summary
            let tx_out_summary = TxSummaryAddTxOut::new(
                n as u8,
                o.masked_amount.as_ref(),
                o.target_key,
                o.public_key,
                o.associated_to_input_rules,
            );

            // Submit tx out summary
            let resp = self
                .request::<TxInfo>(tx_out_summary, &mut buff, self.info.request_timeout)
                .await?;

            // Check state and expected digest
            check_state(resp.state, TxState::SummaryAddTxOut)?;
            //check_digest::<T>(&resp.digest, &ctx.digest)?;

            log::debug!("Address: {:?}", u.address);

            let fog_info = match u
                .address
                .as_ref()
                .map(|a| (a.fog_report_url(), a.fog_authority_sig()))
            {
                Some((Some(url), Some(s))) => {
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(s);
                    Some((url, sig))
                }
                None | Some((None, None)) => None,
                _ => panic!("Fog url and signature must be both present or both absent"),
            };

            // Build tx out unblinding
            let tx_out_unblinding = TxSummaryAddTxOutUnblinding::new(
                n as u8,
                &u.unmasked_amount,
                u.address.as_ref().map(|a| (a, ShortAddressHash::from(a))),
                fog_info,
                u.tx_private_key.map(|k| k.into()),
            )?;

            // Submit tx out unblinding
            let resp = self
                .request::<TxInfo>(tx_out_unblinding, &mut buff, self.info.request_timeout)
                .await?;

            // Check state and expected digest
            let expected_state = match n < summary.outputs.len() - 1 {
                true => TxState::SummaryAddTxOut,
                false => TxState::SummaryAddTxIn,
            };
            check_state(resp.state, expected_state)?;
            //check_digest::<T>(&resp.digest, &ctx.digest)?;
        }

        warn!("Write {} TxIns", summary.inputs.len());

        for n in 0..summary.inputs.len() {
            let i = &summary.inputs[n];
            let u = &unblinding.inputs[n];

            let input_rules_digest = match i.input_rules_digest.len() == 32 {
                true => {
                    let mut b = [0u8; 32];
                    b.copy_from_slice(&i.input_rules_digest[..32]);
                    Some(b)
                }
                false => None,
            };

            // Build TxIn summary
            let tx_in_summary = TxSummaryAddTxIn::new(
                n as u8,
                i.pseudo_output_commitment,
                u.clone(),
                input_rules_digest.as_ref(),
            );

            // Submit tx out unblinding
            let resp = self
                .request::<TxInfo>(tx_in_summary, &mut buff, self.info.request_timeout)
                .await?;

            // Check state and expected digest
            let expected_state = match n < summary.inputs.len() - 1 {
                true => TxState::SummaryAddTxIn,
                false => TxState::SummaryReady,
            };
            check_state(resp.state, expected_state)?;
            //check_digest::<T>(&resp.digest, &ctx.digest)?;
        }

        warn!("Complete Tx Summary");

        let b = TxSummaryBuild {
            fee_value: summary.fee,
            fee_token_id: summary.fee_token_id,
            tombstone_block: summary.tombstone_block,
        };

        // Submit summary build request
        let resp = self
            .request::<TxInfo>(b, &mut buff, self.info.request_timeout)
            .await?;

        check_state(resp.state, TxState::Pending)?;
        //check_digest::<T>(&resp.digest, &ctx.digest)?;

        Ok(())
    }
}
