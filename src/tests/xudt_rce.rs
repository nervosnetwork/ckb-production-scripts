#![allow(unused_imports)]

// stdlib or 3rd part lib
use std::collections::HashMap;

// ckb lib
use ckb_crypto::secp::Privkey;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_script::DataLoader;
use ckb_types::{
    bytes::Bytes,
    core::{
        BlockExt,
        Capacity, cell::{CellMeta, CellMetaBuilder, ResolvedTransaction}, DepType, EpochExt, HeaderView, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    H256,
    packed::{
        self, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs,
        WitnessArgsBuilder,
    },
    prelude::*,
};
use lazy_static::lazy_static;
use rand::{Rng, thread_rng};
use rand::rngs::ThreadRng;


// internal lib
use super::{
    blockchain::Script as ExtensionScript,
    xudt_rce_mol::ScriptVec as ExtensionScriptVec,
    xudt_rce_mol::ScriptVecBuilder as ExtensionScriptVecBuilder,
    build_resolved_tx,
    DummyDataLoader,
    MAX_CYCLES,
};
use ckb_types::prelude::Entity;

lazy_static! {
    pub static ref XUDT_RCE_BIN: Bytes =
        Bytes::from(include_bytes!("../../build/xudt_rce").as_ref());
    pub static ref ALWAYS_SUCCESS_BIN: Bytes =
        Bytes::from(include_bytes!("../../build/always_success").as_ref());
    pub static ref EXNTENSION_SCRIPT_0: Bytes =
        Bytes::from(include_bytes!("../../build/extension_script_0").as_ref());
    pub static ref EXNTENSION_SCRIPT_1: Bytes =
        Bytes::from(include_bytes!("../../build/extension_script_1").as_ref());
}

pub fn gen_random_out_point(rng: &mut ThreadRng) -> OutPoint {
    let hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    OutPoint::new(hash, 0)
}

//
// deploy "bin" to cell, then build a script to point it.
//
// it can:
// * build lock script, set is_type to false
// * build type script, set is_type to true
// * build type script without upgrading, set is_type to false
// * build extension script, set is_type to true
// * build extension script without upgrading, set is_type to false
fn build_script(dummy: &mut DummyDataLoader, tx_builder: TransactionBuilder, is_type: bool,
                     bin: &Bytes, args: Bytes) ->
                     (TransactionBuilder, Script) {
    // this hash to make type script in code unique
    // then make "type script hash" unique, which will be code_hash in "type script"
    let hash = ckb_hash::blake2b_256(bin);

    let type_script_in_code = {
        // this args can be anything
        let args = vec![0u8; 32];
        Script::new_builder()
            .args(args.pack())
            .code_hash(hash.pack())
            .hash_type(ScriptHashType::Type.into())
            .build()
    };

    // it not needed to set "type script" when is_type is false
    let cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(bin.len())
                .expect("script capacity")
                .pack(),
        ).type_(Some(type_script_in_code.clone()).pack())
        .build();

    // use "code" hash as out point, which is unique
    let out_point = &OutPoint::new(hash.pack(), 0);

    dummy.cells.insert(
        out_point.clone(),
        (cell, bin.clone()),
    );

    let tx_builder = tx_builder.cell_dep(
        CellDep::new_builder()
            .out_point(out_point.clone())
            .dep_type(DepType::Code.into())
            .build(),
    );
    let code_hash = if is_type {
        ckb_hash::blake2b_256(type_script_in_code.as_slice())
    } else {
        ckb_hash::blake2b_256(bin)
    };
    let hash_type = if is_type {
        ScriptHashType::Type
    } else {
        ScriptHashType::Data
    };

    let script = Script::new_builder()
        .args(args.pack())
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();

    (tx_builder, script)
}


fn build_xudt_args(flags: u32, scripts: Vec<Script>) -> Bytes {
    // note, the types listed here are different than outside
    use molecule::prelude::Entity;
    use molecule::bytes::Bytes;
    use molecule::prelude::Builder;

    let mut result = vec![];
    result.extend(flags.to_le_bytes().as_ref());

    let mut builder  = ExtensionScriptVecBuilder::default();

    for s in scripts {
        builder = builder.push(ExtensionScript::new_unchecked(s.as_slice().into()));
    }

    let s = builder.build();
    result.extend(s.as_slice());

    result.into()
}

fn build_args(lock: [u8; 32], xudt_args: Bytes) -> Bytes {
    let mut res = Bytes::from(lock.as_ref());
    res.extend(xudt_args);
    res
}


pub fn gen_tx(
    dummy: &mut DummyDataLoader,
    _args: Bytes,
    input_count: usize,
    output_count: usize,
    input_amount: Vec<u128>,
    output_amount: Vec<u128>,
    extension_scripts_bin: Vec<&Bytes>,
    rng: &mut ThreadRng,
) -> TransactionView {
    assert_eq!(input_amount.len(), input_count);
    assert_eq!(output_amount.len(), output_count);

    // setup default tx builder
    let dummy_capacity = Capacity::shannons(50000);
    let tx_builder = TransactionBuilder::default();

    let (tx_builder, args) = if !extension_scripts_bin.is_empty() {
        let mut extension_scripts: Vec<Script> = vec![];
        let (tx_builder, e_script) = build_script(dummy, tx_builder, true, extension_scripts_bin[0], vec![0u8; 32].into());
        extension_scripts.push(e_script);

        // xUDT args on "args" field
        let xudt_args = build_xudt_args(1, extension_scripts);
        let args = build_args([0u8; 32], xudt_args);
        (tx_builder, args)
    } else {
        (tx_builder, Bytes::from([0u8; 32].as_ref()))
    };

    let (tx_builder, always_success_script) =
        build_script(dummy, tx_builder, false, &ALWAYS_SUCCESS_BIN, vec![0u8; 32].into());
    let (mut tx_builder, xudt_rce_script) =
        build_script(dummy, tx_builder, true, &XUDT_RCE_BIN, args);

    for i in 0..output_count {
        let amount = output_amount[i];
        tx_builder = tx_builder.output(
            CellOutput::new_builder()
                .type_(Some(xudt_rce_script.clone()).pack())
                .capacity(dummy_capacity.pack())
                .build(),
        ).output_data(amount.to_le_bytes().pack());
    }

    // setup input type script
    for i in 0..input_count {
        let previous_out_point = gen_random_out_point(rng);

        let previous_output_cell = CellOutput::new_builder()
            .capacity(dummy_capacity.pack())
            // give an "always success" lock script for testing
            .lock(always_success_script.clone())
            .type_(Some(xudt_rce_script.clone()).pack())
            .build();
        dummy.cells.insert(
            previous_out_point.clone(),
            (previous_output_cell.clone(), Bytes::from(&input_amount[i].to_le_bytes()[..])),
        );

        // TODO: fill witness here
        let mut random_extra_witness = [0u8; 32];
        rng.fill(&mut random_extra_witness);
        let witness_args = WitnessArgsBuilder::default()
            .extra(Bytes::from(random_extra_witness.to_vec()).pack())
            .build();

        tx_builder = tx_builder
            .input(CellInput::new(previous_out_point, 0))
            .witness(witness_args.as_bytes().pack());
    }

    tx_builder.build()
}

#[test]
fn test_simple_udt() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, Bytes::from(vec![0u8; 32]),
                    1, 1, vec![100], vec![100],
                    vec![], &mut rng);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_udt_failed() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, Bytes::from(vec![0u8; 32]),
                    1, 1, vec![100], vec![200],
                    vec![], &mut rng);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(-52),
    );
}

#[test]
fn test_xudt_extension_returns_success() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, Bytes::from(vec![0u8; 32]),
                    1, 1, vec![100], vec![100],
                    vec![&EXNTENSION_SCRIPT_0], &mut rng);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(|_script, msg| eprintln!("[XUDT debug] {}", msg));
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_xudt_extension_returns_failed() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, Bytes::from(vec![0u8; 32]),
                    1, 1, vec![100], vec![100],
                    vec![&EXNTENSION_SCRIPT_1], &mut rng);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(|_script, msg| eprintln!("[XUDT debug] {}", msg));
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(1),
    );
}
