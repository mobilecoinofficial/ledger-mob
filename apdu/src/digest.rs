//! Helpers for computing APDU / event digests
//!
//! This is used instead of [Digestible] as the same digest must be computed over [ledger_mob_core::engine::Event]s and APDUs.

use sha2::{Digest as _, Sha512_256};

use mc_core::{
    account::PublicSubaddress,
    keys::{SubaddressViewPublic, TxOutPublic},
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature::{CompressedCommitment, ReducedTxOut, Scalar};
use mc_transaction_types::UnmaskedAmount;

use crate::tx::TxPrivateKey;

pub fn digest_tx_init(account_index: &u32, num_rings: u8) -> [u8; 32] {
    Sha512_256::new()
        .chain_update("tx_init")
        .chain_update(account_index.to_le_bytes())
        .chain_update(num_rings.to_le_bytes())
        .finalize()
        .into()
}

pub fn digest_tx_sign_memo(
    subaddress_index: &u64,
    tx_public_key: &TxOutPublic,
    receiver_view_public: &SubaddressViewPublic,
    kind: &[u8; 2],
    payload: &[u8; 48],
) -> [u8; 32] {
    Sha512_256::new()
        .chain_update("sign_memo")
        .chain_update(subaddress_index.to_le_bytes())
        .chain_update(tx_public_key.to_bytes())
        .chain_update(receiver_view_public.to_bytes())
        .chain_update(kind)
        .chain_update(payload)
        .finalize()
        .into()
}

pub fn digest_tx_set_message(m: &[u8]) -> [u8; 32] {
    Sha512_256::new()
        .chain_update("set_message")
        .chain_update(m)
        .finalize()
        .into()
}

pub fn digest_tx_summary_init(
    message: &[u8; 32],
    block_version: &u32,
    num_outputs: &u32,
    num_inputs: &u32,
) -> [u8; 32] {
    Sha512_256::new()
        .chain_update("tx_summary_init")
        .chain_update(message)
        .chain_update(block_version.to_le_bytes())
        .chain_update(num_outputs.to_le_bytes())
        .chain_update(num_inputs.to_le_bytes())
        .finalize()
        .into()
}

pub fn digest_tx_summary_add_output(
    masked_amount: Option<(&CompressedCommitment, &u64, &[u8])>,
    target_key: &CompressedRistrettoPublic,
    public_key: &CompressedRistrettoPublic,
    associated_to_input_rules: bool,
) -> [u8; 32] {
    let mut d = Sha512_256::new().chain_update("tx_summary_add_output");

    if let Some((commitment, value, token_id)) = masked_amount {
        d = d
            .chain_update(commitment.point.as_bytes())
            .chain_update(value.to_le_bytes())
            .chain_update(token_id);
    }

    d = d
        .chain_update(target_key.as_bytes())
        .chain_update(public_key.as_bytes());

    if associated_to_input_rules {
        d.update("associated_to_input_rules");
    }

    d.finalize().into()
}

pub fn digest_tx_summary_add_output_unblinding(
    unmasked_amount: &UnmaskedAmount,
    address: Option<&PublicSubaddress>,
    tx_private_key: Option<&TxPrivateKey>,
    fog_sig: Option<&[u8]>,
    // TODO: add fog info here
) -> [u8; 32] {
    let mut d = Sha512_256::new()
        .chain_update("tx_summary_add_output_unblinding")
        .chain_update(unmasked_amount.value.to_le_bytes())
        .chain_update(unmasked_amount.token_id.to_le_bytes())
        .chain_update(unmasked_amount.blinding.as_bytes());

    if let Some(a) = address {
        d.update(a.view_public.to_bytes());
        d.update(a.spend_public.to_bytes());
    }

    if let Some(k) = tx_private_key {
        d.update(k.to_bytes());
    }

    if let Some(s) = fog_sig {
        d.update(s);
    }

    d.finalize().into()
}

pub fn digest_tx_summary_add_input(
    pseudo_output_commitment: &CompressedCommitment,
    input_rules_digest: Option<&[u8; 32]>,
    unmasked_amount: &UnmaskedAmount,
) -> [u8; 32] {
    let mut d = Sha512_256::new().chain_update(pseudo_output_commitment.point.as_bytes());

    if let Some(i) = input_rules_digest {
        d.update(i);
    }

    d.chain_update(unmasked_amount.value.to_le_bytes())
        .chain_update(unmasked_amount.token_id.to_le_bytes())
        .chain_update(unmasked_amount.blinding.as_bytes())
        .finalize()
        .into()
}

pub fn digest_tx_summary_build(
    fee_value: &u64,
    fee_token: &u64,
    tombstone_block: &u64,
) -> [u8; 32] {
    Sha512_256::new()
        .chain_update("tx_summary_build")
        .chain_update(fee_value.to_le_bytes())
        .chain_update(fee_token.to_le_bytes())
        .chain_update(tombstone_block.to_le_bytes())
        .finalize()
        .into()
}

pub fn digest_ring_init(
    ring_size: u8,
    real_index: u8,
    subaddress_index: &u64,
    value: &u64,
    token_id: &u64,
) -> [u8; 32] {
    Sha512_256::new()
        .chain_update("ring_init")
        .chain_update(ring_size.to_le_bytes())
        .chain_update(real_index.to_le_bytes())
        .chain_update(subaddress_index.to_le_bytes())
        .chain_update(value.to_le_bytes())
        .chain_update(token_id.to_le_bytes())
        .finalize()
        .into()
}

pub fn digest_ring_set_blinding(blinding: &Scalar, output_blinding: &Scalar) -> [u8; 32] {
    Sha512_256::new()
        .chain_update("set_blinding")
        .chain_update(blinding.as_bytes())
        .chain_update(output_blinding.as_bytes())
        .finalize()
        .into()
}

pub fn digest_ring_add_txout(n: u8, tx_out: &ReducedTxOut) -> [u8; 32] {
    Sha512_256::new()
        .chain_update("add_txout")
        .chain_update(n.to_le_bytes())
        .chain_update(tx_out.public_key.as_bytes())
        .chain_update(tx_out.target_key.as_bytes())
        .chain_update(tx_out.commitment.point.as_bytes())
        .finalize()
        .into()
}

pub fn digest_ring_sign() -> [u8; 32] {
    Sha512_256::new().chain_update("sign").finalize().into()
}
