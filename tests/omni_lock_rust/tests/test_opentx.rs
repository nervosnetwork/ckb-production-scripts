#![allow(dead_code)]
mod misc;

use ckb_error::Error;
use ckb_script::TransactionScriptsVerifier;
use ckb_types::packed::Byte32;

use misc::*;
use omni_lock_test::ckb_sys_call::{sys_call_dump_all, CkbSysCall};
use omni_lock_test::dummy_data_loader::DummyDataLoader;
use omni_lock_test::opentx::*;

fn debug_printer_d(_: &Byte32, msg: &str) {
    print!("{}", msg);
}

//#[test]
fn _test_dump_data() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(0, 2, 3);
    config.smt_in_input = true;
    //config.rep_dump_data = true;
    config.scheme = TestScheme::OnWhiteList;

    let lock_args = config.gen_args();
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(lock_args, 3)], &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    sys_call_dump_all(CkbSysCall::new(&resolved_tx.transaction, &data_loader));

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer_d);

    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn gen_opentx_si_all() -> OpentxWitness {
    OpentxWitness::new(
        0,
        0,
        vec![
            OpentxSigInput {
                cmd: OpentxCommand::TxHash,
                arg1: 0,
                arg2: 0,
            },
            OpentxSigInput {
                cmd: OpentxCommand::GroupInputOutputLen,
                arg1: 0,
                arg2: 0,
            },
            OpentxSigInput {
                cmd: OpentxCommand::IndexOutput,
                arg1: 0,
                arg2: CELL_MASK_CAPACITY
                    | CELL_MASK_LOCK_CODE_HASH
                    | CELL_MASK_LOCK_HASH_TYPE
                    | CELL_MASK_LOCK_ARGS
                    | CELL_MASK_TYPE_CODE_HASH
                    | CELL_MASK_TYPE_HASH_TYPE
                    | CELL_MASK_TYPE_ARGS
                    | CELL_MASK_CELL_DATA
                    | CELL_MASK_TYPE_SCRIPT_HASH
                    | CELL_MASK_LOCK_SCRIPT_HASH
                    | CELL_MASK_WHOLE_CELL,
            },
            OpentxSigInput {
                cmd: OpentxCommand::OffsetOutput,
                arg1: 1,
                arg2: CELL_MASK_CAPACITY
                    | CELL_MASK_LOCK_CODE_HASH
                    | CELL_MASK_LOCK_HASH_TYPE
                    | CELL_MASK_LOCK_ARGS
                    | CELL_MASK_TYPE_CODE_HASH
                    | CELL_MASK_TYPE_HASH_TYPE
                    | CELL_MASK_TYPE_ARGS
                    | CELL_MASK_CELL_DATA
                    | CELL_MASK_TYPE_SCRIPT_HASH
                    | CELL_MASK_LOCK_SCRIPT_HASH
                    | CELL_MASK_WHOLE_CELL,
            },
            OpentxSigInput {
                cmd: OpentxCommand::IndexInput,
                arg1: 0,
                arg2: CELL_MASK_CAPACITY
                    | CELL_MASK_LOCK_CODE_HASH
                    | CELL_MASK_LOCK_HASH_TYPE
                    | CELL_MASK_LOCK_ARGS
                    | CELL_MASK_TYPE_CODE_HASH
                    | CELL_MASK_TYPE_HASH_TYPE
                    | CELL_MASK_TYPE_ARGS
                    | CELL_MASK_CELL_DATA
                    | CELL_MASK_TYPE_SCRIPT_HASH
                    | CELL_MASK_LOCK_SCRIPT_HASH
                    | CELL_MASK_WHOLE_CELL,
            },
            OpentxSigInput {
                cmd: OpentxCommand::OffsetInput,
                arg1: 1,
                arg2: CELL_MASK_CAPACITY
                    | CELL_MASK_LOCK_CODE_HASH
                    | CELL_MASK_LOCK_HASH_TYPE
                    | CELL_MASK_LOCK_ARGS
                    | CELL_MASK_TYPE_CODE_HASH
                    | CELL_MASK_TYPE_HASH_TYPE
                    | CELL_MASK_TYPE_ARGS
                    | CELL_MASK_CELL_DATA
                    | CELL_MASK_TYPE_SCRIPT_HASH
                    | CELL_MASK_LOCK_SCRIPT_HASH
                    | CELL_MASK_WHOLE_CELL,
            },
            OpentxSigInput {
                cmd: OpentxCommand::CellInputIndex,
                arg1: 0,
                arg2: INPUT_MASK_TX_HASH
                    | INPUT_MASK_INDEX
                    | INPUT_MASK_SINCE
                    | INPUT_MASK_PREVIOUS_OUTPUT
                    | INPUT_MASK_TX_HASH
                    | INPUT_MASK_WHOLE,
            },
            OpentxSigInput {
                cmd: OpentxCommand::CellInputOffset,
                arg1: 0,
                arg2: INPUT_MASK_TX_HASH
                    | INPUT_MASK_INDEX
                    | INPUT_MASK_SINCE
                    | INPUT_MASK_PREVIOUS_OUTPUT
                    | INPUT_MASK_TX_HASH
                    | INPUT_MASK_WHOLE,
            },
            OpentxSigInput {
                cmd: OpentxCommand::End,
                arg1: 0,
                arg2: 0,
            },
        ],
    )
}

fn run_opentx_case(config: TestConfig) -> Result<u64, Error> {
    let mut config = config;

    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(config.gen_args(), 2)], &mut config);
    let mut tx = sign_tx(&mut data_loader, tx, &mut config);
    if config.id.flags == IDENTITY_FLAGS_DL {
        tx = sign_tx(&mut data_loader, tx, &mut config);
    }
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer_d);
    verifier.verify(MAX_CYCLES)
}

#[test]
fn test_opentx_pubkey_hash() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    config.opentx_sig_input = Option::Some(gen_opentx_si_all());

    let verify_result = run_opentx_case(config);
    verify_result.expect("pass verification");
}

#[test]
fn test_opentx_ethereum() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM, false);
    config.opentx_sig_input = Option::Some(gen_opentx_si_all());

    let verify_result = run_opentx_case(config);
    verify_result.expect("pass verification");
}

#[test]
fn test_opentx_multisig() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_MULTISIG, true);
    config.set_multisig(0, 2, 3);
    config.opentx_sig_input = Option::Some(gen_opentx_si_all());

    config.scheme = TestScheme::OnWhiteList;

    let verify_result = run_opentx_case(config);
    verify_result.expect("pass verification");
}

#[test]
fn test_opentx_dl() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.opentx_sig_input = Option::Some(gen_opentx_si_all());

    let verify_result = run_opentx_case(config);
    verify_result.expect("pass verification");
}

fn check_res_val(res: Result<u64, Error>, expected: Vec<i64>) {
    let err = res.clone().err().expect("pass verification");
    let err_des = err.to_string();
    if expected.is_empty() {
        return;
    }
    for e in expected {
        if err_des.find(&e.to_string()).is_some() {
            return;
        }
    }
    res.expect("unknow errror");
}

#[test]
fn test_opentx_no_end() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    config.opentx_sig_input = Option::Some(OpentxWitness::new(
        1,
        4,
        vec![
            OpentxSigInput {
                cmd: OpentxCommand::TxHash,
                arg1: 0,
                arg2: 0,
            },
            OpentxSigInput {
                cmd: OpentxCommand::GroupInputOutputLen,
                arg1: 0,
                arg2: 0,
            },
        ],
    ));

    let verify_result = run_opentx_case(config);
    check_res_val(verify_result, vec![102]);
}

#[test]
fn test_opentx_zero_witness() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    let mut opentx_witness = gen_opentx_si_all();
    opentx_witness.err_witness_short = true;
    config.opentx_sig_input = Option::Some(opentx_witness);

    let verify_result = run_opentx_case(config);
    check_res_val(verify_result, vec![102]);
}

#[test]
fn test_opentx_rng_witness() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    let mut opentx_witness = gen_opentx_si_all();
    opentx_witness.err_witness_rand = true;
    config.opentx_sig_input = Option::Some(opentx_witness);

    let verify_result = run_opentx_case(config);
    check_res_val(verify_result, vec![102]);
}

#[test]
fn test_opentx_rng_sign() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    let mut opentx_witness = gen_opentx_si_all();
    opentx_witness.err_sign = true;
    config.opentx_sig_input = Option::Some(opentx_witness);

    let verify_result = run_opentx_case(config);
    check_res_val(verify_result, Vec::<i64>::new());
}

#[test]
fn test_opentx_repeated_end() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    let opentx_witness = OpentxWitness::new(
        0,
        0,
        vec![
            OpentxSigInput {
                cmd: OpentxCommand::TxHash,
                arg1: 0,
                arg2: 0,
            },
            OpentxSigInput {
                cmd: OpentxCommand::End,
                arg1: 0,
                arg2: 0,
            },
            OpentxSigInput {
                cmd: OpentxCommand::End,
                arg1: 0,
                arg2: 0,
            },
        ],
    );
    config.opentx_sig_input = Option::Some(opentx_witness);

    let verify_result = run_opentx_case(config);
    check_res_val(verify_result, Vec::<i64>::new());
}

#[test]
fn test_opentx_err_si_cmd() {
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    let opentx_witness = OpentxWitness::new(
        0,
        0,
        vec![
            OpentxSigInput {
                cmd: OpentxCommand::TxHash,
                arg1: 0,
                arg2: 0,
            },
            OpentxSigInput {
                cmd: OpentxCommand::ErrorCmd,
                arg1: 0,
                arg2: 0,
            },
            OpentxSigInput {
                cmd: OpentxCommand::End,
                arg1: 0,
                arg2: 0,
            },
        ],
    );
    config.opentx_sig_input = Option::Some(opentx_witness);

    let verify_result = run_opentx_case(config);
    check_res_val(verify_result, Vec::<i64>::new());
}
