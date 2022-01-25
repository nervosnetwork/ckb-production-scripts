use cardano_serialization_lib as csl;
use ckb_script::TransactionScriptsVerifier;
use ckb_types::bytes::{BufMut, BytesMut};
use csl::crypto::PrivateKey;
use misc::*;

mod misc;

#[test]
fn test_success() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();
    let sk_bytes: [u8; 32] = config.rnd_array_32();

    let privkey = PrivateKey::from_normal_bytes(&sk_bytes).unwrap();
    let pubkey = privkey.to_public();
    let pubkey_hash = blake160(&pubkey.as_bytes());
    let mut identity: BytesMut = BytesMut::with_capacity(21);
    identity.put_u8(0x7);
    identity.put(pubkey_hash);

    let tx = gen_tx(&mut data_loader, identity.freeze(), &mut config);
    let tx = sign_tx(tx, &privkey, &mut config);
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
fn failed_public_key_hash() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();
    let sk_bytes: [u8; 32] = config.rnd_array_32();

    let privkey = PrivateKey::from_normal_bytes(&sk_bytes).unwrap();
    let pubkey = privkey.to_public();
    let mut pubkey_data = pubkey.as_bytes();
    pubkey_data[0] += 1;

    let pubkey_hash = blake160(&pubkey_data);
    let mut identity: BytesMut = BytesMut::with_capacity(21);
    identity.put_u8(0x7);
    identity.put(pubkey_hash);

    let tx = gen_tx(&mut data_loader, identity.freeze(), &mut config);
    let tx = sign_tx(tx, &privkey, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn failed_auth_type() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();
    let sk_bytes: [u8; 32] = config.rnd_array_32();

    let privkey = PrivateKey::from_normal_bytes(&sk_bytes).unwrap();
    let pubkey = privkey.to_public();
    let pubkey_hash = blake160(&pubkey.as_bytes());
    let mut identity: BytesMut = BytesMut::with_capacity(21);
    identity.put_u8(0x6);
    identity.put(pubkey_hash);

    let tx = gen_tx(&mut data_loader, identity.freeze(), &mut config);
    let tx = sign_tx(tx, &privkey, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err())
}

#[test]
fn failed_sign_data() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();
    config.random_sign_data = true;

    let sk_bytes: [u8; 32] = config.rnd_array_32();

    let privkey = PrivateKey::from_normal_bytes(&sk_bytes).unwrap();
    let pubkey = privkey.to_public();
    let pubkey_hash = blake160(&pubkey.as_bytes());
    let mut identity: BytesMut = BytesMut::with_capacity(21);
    identity.put_u8(0x7);
    identity.put(pubkey_hash);

    let tx = gen_tx(&mut data_loader, identity.freeze(), &mut config);
    let tx = sign_tx(tx, &privkey, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn failed_sign_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();
    config.random_sign_pubkey = true;
    let sk_bytes: [u8; 32] = config.rnd_array_32();

    let privkey = PrivateKey::from_normal_bytes(&sk_bytes).unwrap();
    let pubkey = privkey.to_public();
    let pubkey_hash = blake160(&pubkey.as_bytes());
    let mut identity: BytesMut = BytesMut::with_capacity(21);
    identity.put_u8(0x7);
    identity.put(pubkey_hash);

    let tx = gen_tx(&mut data_loader, identity.freeze(), &mut config);
    let tx = sign_tx(tx, &privkey, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn failed_message() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();
    config.random_message = true;
    let sk_bytes: [u8; 32] = config.rnd_array_32();

    let privkey = PrivateKey::from_normal_bytes(&sk_bytes).unwrap();
    let pubkey = privkey.to_public();
    let pubkey_hash = blake160(&pubkey.as_bytes());
    let mut identity: BytesMut = BytesMut::with_capacity(21);
    identity.put_u8(0x7);
    identity.put(pubkey_hash);

    let tx = gen_tx(&mut data_loader, identity.freeze(), &mut config);
    let tx = sign_tx(tx, &privkey, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_success_multi() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();

    let sk_bytes: [u8; 32] = config.rnd_array_32();

    let privkey = PrivateKey::from_normal_bytes(&sk_bytes).unwrap();
    let pubkey = privkey.to_public();
    let pubkey_hash = blake160(&pubkey.as_bytes());
    let mut identity: BytesMut = BytesMut::with_capacity(21);
    identity.put_u8(0x7);
    identity.put(pubkey_hash);

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(identity.freeze(), 3)], &mut config);
    let tx = sign_tx(tx, &privkey, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
