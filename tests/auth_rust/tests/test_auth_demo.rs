#![allow(unused_imports)]
#![allow(dead_code)]

use std::os::unix::thread;

use ckb_crypto::secp::{Generator, Pubkey, Privkey};
use ckb_error::prelude::thiserror::private::AsDynError;
use ckb_script::TransactionScriptsVerifier;
use log::{Level, LevelFilter, Metadata, Record};
use misc::{
    assert_script_error, build_resolved_tx, debug_printer, gen_args, gen_consensus, gen_tx,
    gen_tx_env, gen_tx_with_grouped_args, sign_tx, AlgorithmType, AuthErrorCodeType,
    DummyDataLoader, EntryCategoryType, TestConfig, MAX_CYCLES,
};
use rand::{thread_rng, Rng};

mod misc;

#[test]
fn ckb_verify_const_val() {
    let mut data_loader = DummyDataLoader::new();
    let mut gen_key = Generator::non_crypto_safe_prng(12);
    let privkey = gen_key.gen_privkey();

    let mut config = TestConfig::new(
        AlgorithmType::Ckb,
        EntryCategoryType::Exec,
        privkey.clone(),
        1,
    );
    config.use_const_val = true;

    let ckb_args = gen_args(&config);

    let tx = gen_tx(&mut data_loader, ckb_args, &config);
    let tx = sign_tx(tx, &privkey, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();

    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
    assert!(false);
}

#[test]
fn ckb_verify_const_val2() {
    let mut data_loader = DummyDataLoader::new();
    let mut gen_key = Generator::non_crypto_safe_prng(12);
    let privkey = gen_key.gen_privkey();

    let mut config = TestConfig::new(
        AlgorithmType::Ckb,
        EntryCategoryType::DynamicLinking,
        privkey.clone(),
        1,
    );
    config.use_const_val = true;

    let ckb_args = gen_args(&config);

    let tx = gen_tx(&mut data_loader, ckb_args, &config);
    let tx = sign_tx(tx, &privkey, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();

    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
    assert!(false);
}

/*
#[test]
fn ckb_verify() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();

    let config = TestConfig::new(
        AlgorithmType::Ckb,
        EntryCategoryType::Exec,
        privkey.clone(),
        1,
    );
    let ckb_args = gen_args(&config);

    let tx = gen_tx(&mut data_loader, ckb_args, &config);
    let tx = sign_tx(tx, &privkey, &config);
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
fn ckb_verify_pubkey_failed() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();

    let mut config = TestConfig::new(
        AlgorithmType::Ckb,
        EntryCategoryType::DynamicLinking,
        privkey.clone(),
        1,
    );
    config.incorrect_pubkey = true;
    let ckb_args = gen_args(&config);

    let tx = gen_tx(&mut data_loader, ckb_args, &config);
    let tx = sign_tx(tx, &privkey, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();

    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn ckb_verify_msg_failed() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();

    let mut config = TestConfig::new(
        AlgorithmType::Ckb,
        EntryCategoryType::DynamicLinking,
        privkey.clone(),
        1,
    );
    config.incorrect_msg = true;

    let ckb_args = gen_args(&config);

    let tx = gen_tx(&mut data_loader, ckb_args, &config);
    let tx = sign_tx(tx, &privkey, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();

    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn ckb_verify_multiple() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();

    let config = TestConfig::new(
        AlgorithmType::Ckb,
        EntryCategoryType::DynamicLinking,
        privkey.clone(),
        5,
    );
    let ckb_args = gen_args(&config);

    let tx = gen_tx(&mut data_loader, ckb_args, &config);
    let tx = sign_tx(tx, &privkey, &config);
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
fn ckb_verify_multiple_group() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();

    let config = TestConfig::new(
        AlgorithmType::Ckb,
        EntryCategoryType::DynamicLinking,
        privkey.clone(),
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

    let tx = sign_tx(tx, &privkey, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();

    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
*/