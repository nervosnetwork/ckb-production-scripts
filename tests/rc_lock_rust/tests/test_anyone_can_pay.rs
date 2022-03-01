#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::{Bytes, BytesMut},
    core::ScriptHashType,
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use rand::{thread_rng, Rng, SeedableRng};

use misc::{
    assert_script_error, blake160, build_always_success_script, build_omni_lock_script,
    build_resolved_tx, debug_printer, gen_tx, gen_tx_with_grouped_args, gen_witness_lock, sign_tx,
    sign_tx_by_input_group, sign_tx_hash, DummyDataLoader, TestConfig, TestScheme, ALWAYS_SUCCESS,
    ERROR_DUPLICATED_INPUTS, ERROR_DUPLICATED_OUTPUTS, ERROR_ENCODING, ERROR_NO_PAIR,
    ERROR_OUTPUT_AMOUNT_NOT_ENOUGH, ERROR_PUBKEY_BLAKE160_HASH, ERROR_WITNESS_SIZE,
    IDENTITY_FLAGS_PUBKEY_HASH, MAX_CYCLES, OMNI_LOCK,
};

mod misc;

#[test]
fn test_unlock_by_anyone() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((0, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}

#[test]
fn test_put_output_data() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((0, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(vec![42u8]).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_ENCODING);
}

#[test]
fn test_wrong_output_args() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((0, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    config.set_acp_config(Some((0, 1)));
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NO_PAIR);
}

#[test]
fn test_split_cell() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((0, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![
            output
                .clone()
                .as_builder()
                .lock(script.clone())
                .capacity(44u64.pack())
                .build(),
            output
                .as_builder()
                .lock(script)
                .capacity(44u64.pack())
                .build(),
        ])
        .set_outputs_data(vec![
            Bytes::from(Vec::new()).pack(),
            Bytes::from(Vec::new()).pack(),
        ])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_DUPLICATED_OUTPUTS);
}

#[test]
fn test_merge_cell() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((0, 0)));

    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args.clone());
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(args, 2)], &mut config);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .clone()
            .as_builder()
            .lock(script.clone())
            .capacity(88u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_DUPLICATED_INPUTS);
}

#[test]
fn test_insufficient_pay() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((0, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .clone()
            .as_builder()
            .lock(script.clone())
            .capacity(41u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_OUTPUT_AMOUNT_NOT_ENOUGH);
}

#[test]
fn test_payment_not_meet_requirement() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((1, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .clone()
            .as_builder()
            .lock(script.clone())
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_OUTPUT_AMOUNT_NOT_ENOUGH);
}

#[test]
fn test_no_pair() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((0, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let another_script = build_omni_lock_script(&mut config, vec![42].into());
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .clone()
            .as_builder()
            .lock(another_script.clone())
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NO_PAIR);
}

#[test]
fn test_overflow() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((255, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_OUTPUT_AMOUNT_NOT_ENOUGH);
}

#[test]
fn test_only_pay_ckb() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    // do not accept UDT transfer
    config.set_acp_config(Some((0, 255)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_always_success_script()).pack())
        .build();
    let prev_data = 44u128.to_le_bytes().to_vec().into();
    data_loader
        .cells
        .insert(input.previous_output(), (prev_output, prev_data));
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .type_(Some(build_always_success_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(44u128.to_le_bytes().to_vec()).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}

#[test]
fn test_only_pay_udt() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    // do not accept CKB transfer
    config.set_acp_config(Some((255, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let input_capacity = prev_output.capacity();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_always_success_script()).pack())
        .build();
    let prev_data = 43u128.to_le_bytes().to_vec().into();
    data_loader
        .cells
        .insert(input.previous_output(), (prev_output, prev_data));
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(input_capacity)
            .type_(Some(build_always_success_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(44u128.to_le_bytes().to_vec()).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}

#[test]
fn test_udt_unlock_by_anyone() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((0, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_always_success_script()).pack())
        .build();
    let prev_data = 43u128.to_le_bytes().to_vec().into();
    data_loader
        .cells
        .insert(input.previous_output(), (prev_output, prev_data));
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(43u64.pack())
            .type_(Some(build_always_success_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(44u128.to_le_bytes().to_vec()).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}

#[test]
fn test_udt_overflow() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    // do not accept CKB transfer
    config.set_acp_config(Some((1, 255)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_always_success_script()).pack())
        .build();
    let prev_data = 43u128.to_le_bytes().to_vec().into();
    data_loader
        .cells
        .insert(input.previous_output(), (prev_output, prev_data));
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .type_(Some(build_always_success_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(44u128.to_le_bytes().to_vec()).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_OUTPUT_AMOUNT_NOT_ENOUGH);
}

#[test]
fn test_extended_udt() {
    // we assume the first 16 bytes data represent token amount
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_acp_config(Some((0, 0)));

    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_omni_lock_script(&mut config, args);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_always_success_script()).pack())
        .build();
    let mut prev_data = 43u128.to_le_bytes().to_vec();
    // push junk data
    prev_data.push(42);
    data_loader
        .cells
        .insert(input.previous_output(), (prev_output, prev_data.into()));
    let output = tx.outputs().get(0).unwrap();
    let mut output_udt = 44u128.to_le_bytes().to_vec();
    // push junk data
    output_udt.push(42);
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .type_(Some(build_always_success_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(output_udt).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}
