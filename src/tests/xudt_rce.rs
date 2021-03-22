#![allow(unused_imports)]

// stdlib or 3rd part lib
use std::collections::HashMap;

// ckb lib
use ckb_crypto::secp::Privkey;
use ckb_error::assert_error_eq;
use ckb_script::DataLoader;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::packed::{Byte32, Byte};
use ckb_types::prelude::Entity;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        BlockExt, Capacity, DepType, EpochExt, HeaderView, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    packed::{
        self, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs, WitnessArgsBuilder,
    },
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, error::Error, MerkleProof,
    SparseMerkleTree, H256 as SmtH256,
};

// internal lib
use super::{
    blockchain::Script as ExtensionScript,
    xudt_rce_mol::ScriptVec as ExtensionScriptVec,
    xudt_rce_mol::ScriptVecBuilder as ExtensionScriptVecBuilder,
    build_resolved_tx,
    DummyDataLoader,
    MAX_CYCLES,
};

use ckb_hash::blake2b_256;
use crate::tests::xudt_rce_mol::{RCData, RCDataBuilder, RCRuleBuilder};

lazy_static! {
    pub static ref RCE_HASH: [u8; 32] = [
        1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
    ];
    pub static ref XUDT_RCE_BIN: Bytes =
        Bytes::from(include_bytes!("../../build/xudt_rce").as_ref());
    pub static ref ALWAYS_SUCCESS_BIN: Bytes =
        Bytes::from(include_bytes!("../../build/always_success").as_ref());
    pub static ref EXTENSION_SCRIPT_0: Bytes =
        Bytes::from(include_bytes!("../../build/extension_script_0").as_ref());
    pub static ref EXTENSION_SCRIPT_1: Bytes =
        Bytes::from(include_bytes!("../../build/extension_script_1").as_ref());
    pub static ref EXTENSION_SCRIPT_RCE: Bytes = Bytes::from(RCE_HASH.as_ref());

    pub static ref SMT_EXISTING: SmtH256 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into();
    pub static ref SMT_NOT_EXISTING: SmtH256 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into();
}

const WHITE_LIST : u8 = 0x2;
const BLACK_LIST : u8 = 0x0;

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
// * build RCE cell, is_type = true. Only the Script.code_hash is kept for further use.
//   when in this case, to make "args" passed in unique
fn build_script(
    dummy: &mut DummyDataLoader,
    tx_builder: TransactionBuilder,
    is_type: bool,
    bin: &Bytes,
    args: Bytes,
) -> (TransactionBuilder, Script) {
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
        .capacity(Capacity::bytes(bin.len()).expect("script capacity").pack())
        .type_(Some(type_script_in_code.clone()).pack())
        .build();

    // use "code" hash as out point, which is unique
    let out_point = &OutPoint::new(hash.pack(), 0);

    dummy.cells.insert(out_point.clone(), (cell, bin.clone()));

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

fn build_rce_script(args: &Bytes) -> Script {
    Script::new_builder()
        .args(args.pack())
        .hash_type(ScriptHashType::Type.into())
        .code_hash(Byte32::new(RCE_HASH.clone()))
        .build()
}

fn build_xudt_args(flags: u32, scripts: Vec<Script>) -> Bytes {
    // note, the types listed here are different than outside
    use molecule::bytes::Bytes;
    use molecule::prelude::Builder;
    use molecule::prelude::Entity;

    let mut result = vec![];
    result.extend(flags.to_le_bytes().as_ref());

    let mut builder = ExtensionScriptVecBuilder::default();

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

type SMT = SparseMerkleTree<Blake2bHasher, SmtH256, DefaultStore<SmtH256>>;

fn new_smt(pairs: Vec<(SmtH256, SmtH256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}

// return smt root and proof
fn build_smt_bl(hashes: &Vec<[u8; 32]>) -> (SmtH256, Vec<u8>) {
    let not_existing_pairs : Vec<(SmtH256, SmtH256)> = hashes.clone().into_iter().map(|hash| (hash.into(), SmtH256::zero())).collect();

    // this is the hash on black list, but "hashes" are not on that.
    let key_on_bl1: SmtH256 = [111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0].into();
    let key_on_bl2 : SmtH256 = [222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0].into();
    let pairs = vec![(key_on_bl1, SMT_EXISTING.clone()), (key_on_bl2, SMT_EXISTING.clone())];

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt.merkle_proof(not_existing_pairs.clone().into_iter().map(|(k,_)| k).collect()).expect("gen proof");
    let compiled_proof = proof.clone().compile(not_existing_pairs.clone()).expect("compile proof");
    assert!(compiled_proof.verify::<Blake2bHasher>(smt.root(), not_existing_pairs.clone()).expect("verify compiled proof"));

    return (root.clone(), compiled_proof.into())
}

// return smt root and proof
fn build_smt_wl(hashes: &Vec<[u8; 32]>) -> (SmtH256, Vec<u8>) {
    let existing_pairs: Vec<(SmtH256, SmtH256)> = hashes.clone().into_iter().map(|hash| (hash.into(), SMT_EXISTING.clone())).collect();

    // this is the hash on white list, and "hashes" are on that.
    let key_on_wl1: SmtH256 = [111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0].into();
    let key_on_wl2 : SmtH256 = [222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0].into();
    let mut pairs = vec![(key_on_wl1, SMT_EXISTING.clone()), (key_on_wl2, SMT_EXISTING.clone())];
    pairs.extend(existing_pairs.clone());

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt.merkle_proof(existing_pairs.clone().into_iter().map(|(k,_)| k).collect()).expect("gen proof");
    let compiled_proof = proof.clone().compile(existing_pairs.clone()).expect("compile proof");
    assert!(compiled_proof.verify::<Blake2bHasher>(smt.root(), existing_pairs.clone()).expect("verify compiled proof"));

    return (root.clone(), compiled_proof.into())
}


fn build_rc_rule(smt_root: [u8; 32], is_black: bool) -> ckb_types::bytes::Bytes {
    use molecule::prelude::*;
    use super::blockchain::*;
    use super::xudt_rce_mol::*;

    let flags = if is_black {
        Byte::new(BLACK_LIST)
    } else {
        Byte::new(WHITE_LIST)
    };

    let sr = Byte32::from_slice(smt_root.as_ref()).expect("Byte32");
    let rcrule = RCRuleBuilder::default().flags(flags).smt_root(sr).build();
    let union = RCDataUnion::RCRule(rcrule);

    let res = RCDataBuilder::default().set(union).build();
    let res2 = res.as_slice();

    res2.into()
}

fn build_extension_data(count : u32, rce_index: u32, proof: &Vec<u8>) -> ckb_types::bytes::Bytes {
    use molecule::prelude::*;
    use molecule::bytes::Bytes;
    use super::blockchain::*;
    use super::xudt_rce_mol::*;

    let p : Bytes = proof.clone().into();

    let mut builder = SmtProofVecBuilder::default();
    for i in 0..count {
        if i == rce_index {
            builder = builder.push(SmtProof::new_unchecked(p.clone()));
        } else {
            builder = builder.push(SmtProof::default());
        }
    }

    let res = builder.build();
    let res2 = res.as_slice();
    res2.into()
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
    let mut tx_builder = TransactionBuilder::default();

    let (tx0, always_success_script) = build_script(
        dummy,
        tx_builder,
        false,
        &ALWAYS_SUCCESS_BIN,
        vec![0u8; 32].into(),
    );
    tx_builder = tx0;
    let always_success_script_hash = blake2b_256(always_success_script.as_slice());

    let (smt_root, proof) = build_smt_wl(&vec![always_success_script_hash]);

    let rce_cell_content = build_rc_rule(smt_root.into(), false);

    let mut total_count = 0;
    let mut rce_index = 0;
    // this is the default args, without XUDT extension: Simple UDT
    let mut args = Bytes::from([0u8; 32].as_ref());
    if !extension_scripts_bin.is_empty() {
        let mut extension_scripts: Vec<Script> = vec![];
        for e_script in extension_scripts_bin {
            if e_script == EXTENSION_SCRIPT_RCE.as_ref() {
                // let's first build the RCE cell which contains the RCData(RCRule/RCCellVec).
                let rce_cell = build_rce_script(&rce_cell_content);
                let rce_cell_hash = rce_cell.code_hash();
                // then create a script with args pointed to that RCE cell
                let e_script = build_rce_script(&rce_cell_hash.as_bytes());
                extension_scripts.push(e_script);
                rce_index = total_count;
            } else {
                let (b0, e_script) =
                    build_script(dummy, tx_builder, true, e_script, vec![0u8; 32].into());
                tx_builder = b0;
                extension_scripts.push(e_script);
            }
            total_count += 1;
        }
        // xUDT args on "args" field
        let xudt_args = build_xudt_args(1, extension_scripts);
        args = build_args([0u8; 32], xudt_args);
    }
    build_extension_data(total_count, rce_index, &proof);

    let (mut tx_builder, xudt_rce_script) =
        build_script(dummy, tx_builder, true, &XUDT_RCE_BIN, args);

    for i in 0..output_count {
        let amount = output_amount[i];
        tx_builder = tx_builder
            .output(
                CellOutput::new_builder()
                    .lock(always_success_script.clone())
                    .type_(Some(xudt_rce_script.clone()).pack())
                    .capacity(dummy_capacity.pack())
                    .build(),
            )
            .output_data(amount.to_le_bytes().pack());
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
            (
                previous_output_cell.clone(),
                Bytes::from(&input_amount[i].to_le_bytes()[..]),
            ),
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

fn debug_printer(script: &Byte32, msg: &str) {
    let slice = script.as_slice();
    let str = format!(
        "Script({:x}{:x}{:x}{:x}{:x})",
        slice[0], slice[1], slice[2], slice[3], slice[4]
    );
    println!("{:?}: {}", str, msg);
}

#[test]
fn test_simple_udt() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        vec![],
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_udt_failed() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![200],
        vec![],
        &mut rng,
    );
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
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        vec![&EXTENSION_SCRIPT_0],
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_xudt_extension_multi_return_success() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let bin_vec: Vec<&Bytes> = vec![
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
    ];
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_xudt_extension_returns_failed() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        vec![&EXTENSION_SCRIPT_1],
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(1),
    );
}

#[test]
fn test_xudt_extension_multi_return_failed() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let bin_vec: Vec<&Bytes> = vec![
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_1,
    ];
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(1),
    );
}
