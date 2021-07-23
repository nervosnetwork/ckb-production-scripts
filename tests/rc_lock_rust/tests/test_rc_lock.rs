#![allow(unused_imports)]
#![allow(dead_code)]

mod misc;

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

//
// owner lock section
//
#[test]
fn test_simple_owner_lock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_owner_lock_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_owner_lock_mismatched() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.scheme = TestScheme::OwnerLockMismatched;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result
        .unwrap_err()
        .to_string()
        .contains("error code 70"));
}

#[test]
fn test_owner_lock_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_owner_lock_on_wl_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::OnWhiteList;
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_owner_lock_not_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::NotOnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result
        .unwrap_err()
        .to_string()
        .contains("error code 59"));
}

#[test]
fn test_owner_lock_no_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    // only black list is used, but not on it.
    // but rc_lock requires at least one white list
    config.scheme = TestScheme::NotOnBlackList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result
        .unwrap_err()
        .to_string()
        .contains("error code 83"));
}

#[test]
fn test_owner_lock_on_bl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::BothOn;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result
        .unwrap_err()
        .to_string()
        .contains("error code 57"));
}

#[test]
fn test_owner_lock_emergency_halt_mode() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::EmergencyHaltMode;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result
        .unwrap_err()
        .to_string()
        .contains("error code 54"));
}

//
// pubkey hash section
//

#[test]
fn test_pubkey_hash_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_pubkey_hash_on_wl_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_pubkey_hash_not_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::NotOnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result
        .unwrap_err()
        .to_string()
        .contains("error code 59"));
}

#[test]
fn test_pubkey_hash_no_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    // only black list is used, but not on it.
    // but rc_lock requires at least one white list
    config.scheme = TestScheme::NotOnBlackList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result
        .unwrap_err()
        .to_string()
        .contains("error code 83"));
}

#[test]
fn test_pubkey_hash_on_bl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::BothOn;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result
        .unwrap_err()
        .to_string()
        .contains("error code 57"));
}

#[test]
fn test_pubkey_hash_emergency_halt_mode() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::EmergencyHaltMode;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result
        .unwrap_err()
        .to_string()
        .contains("error code 54"));
}
