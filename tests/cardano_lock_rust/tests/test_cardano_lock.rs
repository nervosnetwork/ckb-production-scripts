use ckb_script::TransactionScriptsVerifier;
use ckb_types::bytes::{BufMut, Bytes, BytesMut};
use misc::*;

mod misc;

#[test]
fn test_success() {
    let mut data_loader = DummyDataLoader::new();
    let mut config = Config::new();

    let mut args: BytesMut = BytesMut::with_capacity(65);
    args.put_u8(0b0000 << 4 + 0000);
    args.put(blake_224(&config.privkey.to_public().as_bytes()));
    args.put(Bytes::from(vec![0; 28]));

    let tx = gen_tx(&mut data_loader, args.freeze(), &mut config);
    let tx = sign_tx(tx, &mut config);
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

    let mut args: BytesMut = BytesMut::with_capacity(64);
    args.put(Bytes::from(config.rnd_array_28().to_vec()));
    args.put(Bytes::from(vec![0; 28]));

    let tx = gen_tx(&mut data_loader, args.freeze(), &mut config);
    let tx = sign_tx(tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err(), "pass verification");
}

#[test]
fn failed_sign_data() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();
    config.random_sign_data = true;

    let mut args: BytesMut = BytesMut::with_capacity(64);
    args.put(blake_224(&config.privkey.to_public().as_bytes()));
    args.put(Bytes::from(vec![0; 32]));

    let tx = gen_tx(&mut data_loader, args.freeze(), &mut config);
    let tx = sign_tx(tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err(), "pass verification");
}

#[test]
fn failed_sign_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();
    config.random_sign_pubkey = true;

    let mut args: BytesMut = BytesMut::with_capacity(64);
    args.put(blake_224(&config.privkey.to_public().as_bytes()));
    args.put(Bytes::from(vec![0; 32]));

    let tx = gen_tx(&mut data_loader, args.freeze(), &mut config);
    let tx = sign_tx(tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err(), "pass verification");
}

#[test]
fn failed_message() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();
    config.random_message = true;

    let mut args: BytesMut = BytesMut::with_capacity(64);
    args.put(blake_224(&config.privkey.to_public().as_bytes()));
    args.put(Bytes::from(vec![0; 32]));

    let tx = gen_tx(&mut data_loader, args.freeze(), &mut config);
    let tx = sign_tx(tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err(), "pass verification");
}

#[test]
fn test_success_multi() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = Config::new();

    let mut args: BytesMut = BytesMut::with_capacity(64);
    args.put_u8(0b0000 << 4 + 0000);
    args.put(blake_224(&config.privkey.to_public().as_bytes()));
    args.put(Bytes::from(vec![0; 28]));

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(args.freeze(), 3)], &mut config);
    let tx = sign_tx(tx, &mut config);
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
fn failed_random_away() {
    for _i in 0..100 {
        failed_sign_data()
    }
}

#[test]
fn failed_header_type() {
    let mut data_loader = DummyDataLoader::new();
    let mut config = Config::new();

    let mut args: BytesMut = BytesMut::with_capacity(65);
    args.put_u8(0b1000 << 4 + 0000);
    args.put(blake_224(&config.privkey.to_public().as_bytes()));
    args.put(Bytes::from(vec![0; 28]));

    let tx = gen_tx(&mut data_loader, args.freeze(), &mut config);
    let tx = sign_tx(tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err(), "pass verification");
}

#[test]
fn test_success_only_pubkey() {
    let mut data_loader = DummyDataLoader::new();
    let mut config = Config::new();

    let mut args: BytesMut = BytesMut::with_capacity(65);
    args.put_u8(0b0110 << 4 + 0000);
    args.put(blake_224(&config.privkey.to_public().as_bytes()));

    let tx = gen_tx(&mut data_loader, args.freeze(), &mut config);
    let tx = sign_tx(tx, &mut config);
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
fn fiailed_only_pubkey() {
    let mut data_loader = DummyDataLoader::new();
    let mut config = Config::new();

    let mut args: BytesMut = BytesMut::with_capacity(65);
    args.put_u8(0b0110 << 4 + 0000);
    let pubkey_hash = blake_224(&config.privkey.to_public().as_bytes()).to_vec();
    let tmp_pubkey = &pubkey_hash[0..27];
    args.put(Bytes::from(tmp_pubkey.to_vec()));

    let tx = gen_tx(&mut data_loader, args.freeze(), &mut config);
    let tx = sign_tx(tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err(), "pass verification");
}

#[test]
fn fiailed_only_pubkey2() {
    let mut data_loader = DummyDataLoader::new();
    let mut config = Config::new();

    let mut args: BytesMut = BytesMut::with_capacity(65);
    args.put_u8(0b1111 << 4 + 0000);
    args.put(blake_224(&config.privkey.to_public().as_bytes()));

    let tx = gen_tx(&mut data_loader, args.freeze(), &mut config);
    let tx = sign_tx(tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err(), "pass verification");
}

#[test]
fn test_blake2b_224() {
    let config = Config::new();
    let pubkey = config.privkey.to_public();

    let hash1 = blake_224(&pubkey.as_bytes()).to_vec();
    let hash2 = pubkey.hash().to_bytes();
    assert_eq!(hash1, hash2);
}
