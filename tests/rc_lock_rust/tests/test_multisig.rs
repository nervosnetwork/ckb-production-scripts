#![allow(unused_imports)]
#![allow(dead_code)]

mod misc;

use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, ScriptGroupType, TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::{
    bytes::Bytes,
    bytes::BytesMut,
    core::{
        cell::ResolvedTransaction, hardfork::HardForkSwitch, EpochNumberWithFraction, HeaderView,
    },
    packed::WitnessArgs,
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use misc::*;
use rc_lock_test::debug_utils::debug;
use std::fs;

// Script args validation errors
const ERROR_INVALID_RESERVE_FIELD: i8 = -41;
const ERROR_INVALID_PUBKEYS_CNT: i8 = -42;
const ERROR_INVALID_THRESHOLD: i8 = -43;
const ERROR_INVALID_REQUIRE_FIRST_N: i8 = -44;
const ERROR_MULTSIG_SCRIPT_HASH: i8 = -51;
const ERROR_VERIFICATION: i8 = -52;

#[test]
fn test_multisig_0_2_3_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(0, 2, 3);

    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_multisig_invalid_flags() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(0, 2, 3);
    config.multisig.set(0, 2, 4);

    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_MULTSIG_SCRIPT_HASH)
}

#[test]
fn test_multisig_invalid_flags2() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(0, 2, 3);
    config.multisig.set(0, 3, 3);

    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_MULTSIG_SCRIPT_HASH)
}

#[test]
fn test_multisig_1_2_3_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(1, 2, 3);

    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_multisig_3_7_15_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(3, 7, 15);

    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_multisig_0_1_1_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(0, 1, 1);

    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_multisig_0_2_2_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(0, 2, 2);

    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
#[ignore]
fn test_multisig_0_2_3_unlock_smt_in_input_debug() {
    let binary = fs::read("../../../build/rc_lock.debug").expect("read_to_string");
    let rc_lock_debug = Bytes::from(binary);

    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(0, 2, 3);
    config.smt_in_input = true;

    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);

    debug(
        "127.0.0.1:9999",
        ScriptGroupType::Lock,
        config.running_script.calc_script_hash(),
        &rc_lock_debug,
        &[],
        &verifier,
    );
}

#[test]
fn test_multisig_0_2_3_unlock_smt_in_input() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(0, 2, 3);
    config.smt_in_input = true;

    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
