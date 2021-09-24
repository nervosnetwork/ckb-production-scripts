#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::{Generator, Pubkey};
use ckb_script::TransactionScriptsVerifier;
use log::{Level, LevelFilter, Metadata, Record};
use misc::{
    build_resolved_tx, debug_printer, gen_args, gen_consensus, gen_tx, gen_tx_env, sign_tx,
    AlgorithmType, DummyDataLoader, EntryCategoryType, TestConfig, MAX_CYCLES,
};

mod misc;

#[test]
fn test_ckb_verify() {
    // TODO can print return value
    log::set_boxed_logger(Box::new(misc::MyLogger {})).unwrap();
    log::set_max_level(LevelFilter::Info);

    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");

    let config = TestConfig {
        algorithm_type: AlgorithmType::Ckb,
        entry_category_type: EntryCategoryType::DynamicLinking,
        pubkey,
    };
    let ckb_args = gen_args(config);

    let tx = gen_tx(&mut data_loader, ckb_args);
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();

    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
