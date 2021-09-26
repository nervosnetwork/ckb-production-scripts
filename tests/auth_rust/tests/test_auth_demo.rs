#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::{Generator, Pubkey};
use ckb_error::{prelude::thiserror::private::AsDynError, Error};
use ckb_script::TransactionScriptsVerifier;
use log::{Level, LevelFilter, Metadata, Record};
use misc::{
    assert_script_error, build_resolved_tx, debug_printer, gen_args, gen_consensus, gen_tx,
    gen_tx_env, gen_tx_with_grouped_args, sign_tx, AlgorithmType, AuthErrorCodeType,
    DummyDataLoader, EntryCategoryType, TestConfig, MAX_CYCLES,
};
use rand::{thread_rng, Rng};

mod misc;

fn verify_unit(config: &TestConfig) -> Result<u64, Error> {
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, &config);
    let tx = sign_tx(tx, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();

    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    verifier.verify(MAX_CYCLES)
}

#[test]
fn ckb_verify() {
    let auth = misc::auth_builder(AlgorithmType::Ckb).unwrap();
    let config = TestConfig::new(
        auth,
        EntryCategoryType::DynamicLinking,
        1,
    );

    let verify_result = verify_unit(&config);    
    verify_result.expect("pass verification");
}

#[test]
fn ckb_verify_pubkey_failed() {
    let auth = misc::auth_builder(AlgorithmType::Ckb).unwrap();
    let mut config = TestConfig::new(
        auth,
        EntryCategoryType::DynamicLinking,
        1,
    );
    config.incorrect_pubkey = true;

    let verify_result = verify_unit(&config);    
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn ckb_verify_msg_failed() {
    let auth = misc::auth_builder(AlgorithmType::Ckb).unwrap();
    let mut config = TestConfig::new(
        auth,
        EntryCategoryType::DynamicLinking,
        1,
    );
    config.incorrect_msg = true;

    let verify_result = verify_unit(&config);    
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn ckb_verify_multiple() {
    let auth = misc::auth_builder(AlgorithmType::Ckb).unwrap();
    let config = TestConfig::new(
        auth,
        EntryCategoryType::DynamicLinking,
        5,
    );

    let verify_result = verify_unit(&config);    
    verify_result.expect("pass verification");
}

#[test]
fn ckb_verify_multiple_group() {
    let mut data_loader = DummyDataLoader::new();

    let auth = misc::auth_builder(AlgorithmType::Ckb).unwrap();
    let config = TestConfig::new(
        auth,
        EntryCategoryType::DynamicLinking,
        1,
    );

    let mut rng = thread_rng();
    let tx = gen_tx_with_grouped_args(
        &mut data_loader,
        vec![
            (gen_args(&config), 1),
            (gen_args(&config), 1),
            (gen_args(&config), 1),
        ],
        &mut rng,
    );

    let tx = sign_tx(tx, &config);
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
fn ethereum_verify() {
    let auth = misc::auth_builder(AlgorithmType::Ethereum).unwrap();
    let config = TestConfig::new(
        auth,
        EntryCategoryType::DynamicLinking,
        1,
    );
    let verify_result = verify_unit(&config);    
    verify_result.expect("pass verification");
}

#[test]
fn ethereum_verify_failed() {
    let auth = misc::auth_builder(AlgorithmType::Ethereum).unwrap();
    let mut config = TestConfig::new(
        auth,
        EntryCategoryType::DynamicLinking,
        1,
    );
    config.incorrect_msg = true;

    let verify_result = verify_unit(&config);    
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

