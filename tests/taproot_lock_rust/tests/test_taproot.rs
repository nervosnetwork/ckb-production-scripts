#![allow(unused_imports)]
#![allow(dead_code)]

mod misc;
use env_logger;

use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier, TxVerifyEnv};
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

#[test]
fn test_key_path_spending_success() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new();
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
fn test_script_path_spending_success() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new();
    config.set_script_path_spending();

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
fn test_script_path_spending_wrong_output_key() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new();
    config.set_script_path_spending();
    config.scheme = TestScheme::WrongOutputKey;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_SCHNORR);
}
