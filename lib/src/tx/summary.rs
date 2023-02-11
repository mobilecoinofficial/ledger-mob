// Copyright (c) 2022-2023 The MobileCoin Foundation

use log::warn;
use std::ops::Deref;

use mc_core::account::ShortAddressHash;
use mc_transaction_core::{BlockVersion, TxSummary};
use mc_transaction_summary::TxSummaryUnblindingData;

use ledger_mob_apdu::{state::TxState, tx::*};
use ledger_transport::Exchange;

use super::{check_state, TransactionHandle};
use crate::Error;

impl<T: Exchange + Send + Sync> TransactionHandle<T>
where
    <T as Exchange>::Error: Send + Sync,
{
    /// Load tx summary for signing operation, alternative to `set_message` for block versions > 3
    pub async fn set_tx_summary(
        &self,
        block_version: BlockVersion,
        message: &[u8],
        summary: &TxSummary,
        unblinding: &TxSummaryUnblindingData,
    ) -> Result<(), Error<<T as Exchange>::Error>> {
        let mut buff = [0u8; 256];
        let ctx = self.ctx.lock().await;

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
        let resp = ctx.exchange::<TxInfo>(init, &mut buff).await?;

        // Check state and expected digest
        check_state::<T>(resp.state, TxState::SummaryInit)?;
        //check_digest::<T>(&resp.digest, &ctx.digest)?;

        warn!("Write {} TxOuts", summary.outputs.len());

        // Write outputs to summary
        if summary.outputs.len() != unblinding.outputs.len() {}

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
            let resp = ctx.exchange::<TxInfo>(tx_out_summary, &mut buff).await?;

            // Check state and expected digest
            check_state::<T>(resp.state, TxState::SummaryAddTxOut)?;
            //check_digest::<T>(&resp.digest, &ctx.digest)?;

            // Build tx out unblinding
            let tx_out_unblinding = TxSummaryAddTxOutUnblinding::new(
                n as u8,
                &u.unmasked_amount,
                u.address.as_ref().map(|a| (a, ShortAddressHash::from(a))),
                u.tx_private_key.map(|k| k.into()),
            );

            // Submit tx out unblinding
            let resp = ctx.exchange::<TxInfo>(tx_out_unblinding, &mut buff).await?;

            // Check state and expected digest
            let expected_state = match n < summary.outputs.len() - 1 {
                true => TxState::SummaryAddTxOut,
                false => TxState::SummaryAddTxIn,
            };
            check_state::<T>(resp.state, expected_state)?;
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
            let resp = ctx.exchange::<TxInfo>(tx_in_summary, &mut buff).await?;

            // Check state and expected digest
            let expected_state = match n < summary.inputs.len() - 1 {
                true => TxState::SummaryAddTxIn,
                false => TxState::SummaryReady,
            };
            check_state::<T>(resp.state, expected_state)?;
            //check_digest::<T>(&resp.digest, &ctx.digest)?;
        }

        warn!("Complete Tx Summary");

        let b = TxSummaryBuild {
            fee_value: summary.fee,
            fee_token_id: summary.fee_token_id,
            tombstone_block: summary.tombstone_block,
        };

        // Submit summary build request
        let resp = ctx.exchange::<TxInfo>(b, &mut buff).await?;

        check_state::<T>(resp.state, TxState::Pending)?;
        //check_digest::<T>(&resp.digest, &ctx.digest)?;

        Ok(())
    }
}
