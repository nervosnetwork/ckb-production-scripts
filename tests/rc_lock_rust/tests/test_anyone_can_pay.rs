
#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::{Bytes, BytesMut},
    core::{ScriptHashType},
    packed::{WitnessArgs, Script, CellOutput},
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use rand::{thread_rng, Rng, SeedableRng};

use misc::{
    blake160, build_resolved_tx, debug_printer, gen_tx, gen_tx_with_grouped_args, gen_witness_lock,
    sign_tx, sign_tx_by_input_group, sign_tx_hash, DummyDataLoader, TestConfig, TestScheme,
    ERROR_ENCODING, ERROR_PUBKEY_BLAKE160_HASH, ERROR_WITNESS_SIZE, IDENTITY_FLAGS_PUBKEY_HASH,
    MAX_CYCLES,
    RC_LOCK,
    ALWAYS_SUCCESS,
};

mod misc;

fn build_rc_lock_script(config: &mut TestConfig, args: Bytes) -> Script {
    let args = if config.is_owner_lock() {
        if config.scheme == TestScheme::OwnerLockMismatched {
            config.id.blake160 = {
                let mut buf = BytesMut::new();
                buf.resize(20, 0);
                buf.freeze()
            };
            config.gen_args()
        } else {
            config.gen_args()
        }
    } else {
        if config.is_rc() {
            config.gen_args()
        } else {
            args
        }
    };
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&RC_LOCK);
    Script::new_builder()
        .args(args.pack())
        .code_hash(sighash_all_cell_data_hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .build()
}

fn build_udt_script() -> Script {
    let data_hash = CellOutput::calc_data_hash(&ALWAYS_SUCCESS);
    Script::new_builder()
        .code_hash(data_hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .build()
}

#[test]
fn test_unlock_by_anyone() {
    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_use_acp(Some((0, 0)));
    let tx = gen_tx(&mut data_loader, &mut config);
    let args = config.gen_args();
    let script = build_rc_lock_script(&mut config, args);
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
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}

/*
#[test]
fn test_put_output_data() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash);
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
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_ENCODING),
    );
}

#[test]
fn test_wrong_output_args() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash.to_owned());
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock({
                let mut args = pubkey_hash.to_vec();
                // a valid args
                args.push(0);
                script.as_builder().args(Bytes::from(args).pack()).build()
            })
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_NO_PAIR),
    );
}

#[test]
fn test_split_cell() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash.to_owned());
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
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_DUPLICATED_OUTPUTS),
    );
}

#[test]
fn test_merge_cell() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let mut rng = thread_rng();
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(pubkey_hash, 2)], &mut rng);
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
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_DUPLICATED_INPUTS),
    );
}

#[test]
fn test_insufficient_pay() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash);
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
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_OUTPUT_AMOUNT_NOT_ENOUGH),
    );
}

#[test]
fn test_payment_not_meet_requirement() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    let mut args = pubkey_hash.to_vec();
    args.push(1);
    let args = Bytes::from(args);
    let script = build_anyone_can_pay_script(args.clone());
    let tx = gen_tx(&mut data_loader, args);
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
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_OUTPUT_AMOUNT_NOT_ENOUGH),
    );
}

#[test]
fn test_no_pair() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    let another_script = build_anyone_can_pay_script(vec![42].into());
    let tx = gen_tx(&mut data_loader, pubkey_hash.to_owned());
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
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_NO_PAIR),
    );
}

#[test]
fn test_overflow() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    let mut args = pubkey_hash.to_vec();
    args.push(255);
    let args = Bytes::from(args);

    let script = build_anyone_can_pay_script(args.to_owned());
    let tx = gen_tx(&mut data_loader, args);
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
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);

    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_OUTPUT_AMOUNT_NOT_ENOUGH),
    );
}

#[test]
fn test_only_pay_ckb() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    let mut args = pubkey_hash.to_vec();
    args.push(0);
    // do not accept UDT transfer
    args.push(255);
    let args = Bytes::from(args);

    let script = build_anyone_can_pay_script(args.to_owned());
    let tx = gen_tx(&mut data_loader, args);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_udt_script()).pack())
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
            .type_(Some(build_udt_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(44u128.to_le_bytes().to_vec()).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.unwrap();
}

#[test]
fn test_only_pay_udt() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let mut args = {
        let pubkey_hash = blake160(&pubkey.serialize());
        pubkey_hash.to_vec()
    };
    args.push(255);
    let args = Bytes::from(args);

    let script = build_anyone_can_pay_script(args.to_owned());
    let tx = gen_tx(&mut data_loader, args);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let input_capacity = prev_output.capacity();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_udt_script()).pack())
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
            .capacity(input_capacity)
            .type_(Some(build_udt_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(44u128.to_le_bytes().to_vec()).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}

#[test]
fn test_udt_unlock_by_anyone() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_udt_script()).pack())
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
            .type_(Some(build_udt_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(44u128.to_le_bytes().to_vec()).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}

#[test]
fn test_udt_overflow() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    let mut args = pubkey_hash.to_vec();
    args.push(1);
    args.push(255);
    let args = Bytes::from(args);

    let script = build_anyone_can_pay_script(args.to_owned());
    let tx = gen_tx(&mut data_loader, args);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_udt_script()).pack())
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
            .type_(Some(build_udt_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(44u128.to_le_bytes().to_vec()).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);

    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_OUTPUT_AMOUNT_NOT_ENOUGH),
    );
}

#[test]
fn test_extended_udt() {
    // we assume the first 16 bytes data represent token amount
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let input = tx.inputs().get(0).unwrap();
    let (prev_output, _) = data_loader.cells.remove(&input.previous_output()).unwrap();
    let prev_output = prev_output
        .as_builder()
        .type_(Some(build_udt_script()).pack())
        .build();
    let mut prev_data = 44u128.to_le_bytes().to_vec();
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
            .type_(Some(build_udt_script()).pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(output_udt).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}
*/
