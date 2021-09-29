#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::{Generator, Pubkey};
use ckb_error::{prelude::thiserror::private::AsDynError, Error};
use ckb_script::TransactionScriptsVerifier;
use log::{Level, LevelFilter, Metadata, Record};
use rand::{thread_rng, Rng};
use sha3::digest::DynDigest;

use misc::{
    assert_script_error, auth_builder, build_resolved_tx, debug_printer, gen_args, gen_consensus,
    gen_tx, gen_tx_env, gen_tx_with_grouped_args, sign_tx, AlgorithmType, AuthErrorCodeType,
    DummyDataLoader, EntryCategoryType, TestConfig, MAX_CYCLES,
};
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

fn unit_test_with_type(t: AlgorithmType, incorrect_pubkey: bool) -> Result<u64, Error> {
    unit_test_with_auth(auth_builder(t).unwrap(), incorrect_pubkey)
}

fn unit_test_with_auth(auth: Box<dyn misc::Auth>, incorrect_pubkey: bool) -> Result<u64, Error> {
    let mut config = TestConfig::new(auth, EntryCategoryType::Exec, 1);
    config.incorrect_pubkey = incorrect_pubkey;

    verify_unit(&config)
}

fn unit_test_success(t: AlgorithmType) {
    unit_test_with_type(t, false).expect("pass verification");
}

fn unit_test_failed(t: AlgorithmType) {
    let verify_result = unit_test_with_type(t, true);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn ckb_verify() {
    unit_test_success(AlgorithmType::Ckb);
}

#[test]
fn ckb_verify_pubkey_failed() {
    let auth = auth_builder(AlgorithmType::Ckb).unwrap();
    let mut config = TestConfig::new(auth, EntryCategoryType::DynamicLinking, 1);
    config.incorrect_pubkey = true;

    let verify_result = verify_unit(&config);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn ckb_verify_msg_failed() {
    unit_test_failed(AlgorithmType::Ckb);
}

#[test]
fn ckb_verify_multiple() {
    let auth = auth_builder(AlgorithmType::Ckb).unwrap();
    let config = TestConfig::new(auth, EntryCategoryType::DynamicLinking, 5);

    let verify_result = verify_unit(&config);
    verify_result.expect("pass verification");
}

#[test]
fn ckb_verify_multiple_group() {
    let mut data_loader = DummyDataLoader::new();

    let auth = auth_builder(AlgorithmType::Ckb).unwrap();
    let config = TestConfig::new(auth, EntryCategoryType::DynamicLinking, 1);

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
    unit_test_success(AlgorithmType::Ethereum);
}

#[test]
fn ethereum_verify_failed() {
    unit_test_failed(AlgorithmType::Ethereum);
}

#[test]
fn eos_verify() {
    unit_test_success(AlgorithmType::Eos);
}

#[test]
fn eos_verify_failed() {
    unit_test_failed(AlgorithmType::Eos)
}

#[test]
fn tron_verify() {
    unit_test_success(AlgorithmType::Tron);
}

#[test]
fn tron_verify_failed() {
    unit_test_failed(AlgorithmType::Tron);
}

#[test]
fn bitcoin_verify() {
    unit_test_success(AlgorithmType::Bitcoin);
}

#[test]
fn bitcoin_verify_failed() {
    unit_test_failed(AlgorithmType::Bitcoin);
}

#[test]
fn bitcoin_verify_uncompress() {
    let mut auth = misc::BitcoinAuth::new();
    auth.compress = false;
    unit_test_with_auth(auth, false).expect("verify btc failed");
}

#[test]
fn dogecoin_verify() {
    unit_test_success(AlgorithmType::Dogecoin);
}

#[test]
fn dogecoin_verify_failed() {
    unit_test_failed(AlgorithmType::Dogecoin);
}

#[test]
fn ckbmultisig_verify() {
    let auth = misc::CkbMultisigAuth::new(2, 2, 1);

    unit_test_with_auth(auth, false).expect("verify btc failed");
}

#[test]
fn ckbmultisig_verify_failed() {
    let auth = misc::CkbMultisigAuth::new(2, 2, 1);

    let verify_result = unit_test_with_auth(auth, true);
    misc::assert_script_error_i(verify_result.unwrap_err(), -51);
}

#[test]
fn schnorr() {
    let auth = auth_builder(AlgorithmType::SchnorrOrTaproot).unwrap();
    let config = TestConfig::new(auth, EntryCategoryType::Exec, 1);
    let verify_result = verify_unit(&config);
    assert_script_error(
        verify_result.unwrap_err(),
        AuthErrorCodeType::NotImplemented,
    );
}

#[test]
fn rsa_verify() {
    unit_test_success(AlgorithmType::RSA);
}

#[test]
fn rsa_verify_failed() {
    unit_test_failed(AlgorithmType::RSA);
}

/*
#[test]
fn owner_lock() {
    unit_test_success(AlgorithmType::OwnerLock);
}
*/
