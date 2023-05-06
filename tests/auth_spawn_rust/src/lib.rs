pub mod auto_complete;
#[allow(dead_code)]
pub mod combine_lock_mol;
pub mod hash;
pub mod smt;

pub mod blockchain {
    pub use ckb_types::packed::{
        Byte, Byte32, Byte32Reader, Byte32Vec, Byte32VecReader, ByteReader, Bytes, BytesOpt,
        BytesOptReader, BytesReader, BytesVec, BytesVecReader, Script, WitnessArgs,
        WitnessArgsBuilder, WitnessArgsReader,
    };
}
use anyhow;
use anyhow::Context;
use blockchain::Bytes as BlockchainBytes;
use blockchain::WitnessArgs;
use ckb_hash::new_blake2b;
use ckb_types::core::ScriptHashType;
use ckb_types::packed;
use ckb_types::prelude::*;
use combine_lock_mol::{ChildScript, ChildScriptVec, CombineLockWitness, Uint16};
use molecule::bytes::Bytes;
use molecule::prelude::*;
use std::{fs::read_to_string, path::PathBuf};

use auto_complete::auto_complete;
use ckb_debugger_api::embed::Embed;
use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction};
use hash::hash;
use serde_json::from_str as from_json_str;
use smt::build_tree;
use sparse_merkle_tree::H256;

pub fn read_tx_template(file_name: &str) -> Result<ReprMockTransaction, anyhow::Error> {
    let mock_tx =
        read_to_string(file_name).with_context(|| format!("Failed to read from {}", file_name))?;
    let mock_tx = auto_complete(&mock_tx)?;

    let mut mock_tx_embed = Embed::new(PathBuf::from(file_name), mock_tx.clone());
    let mock_tx = mock_tx_embed.replace_all();
    let mut repr_mock_tx: ReprMockTransaction =
        from_json_str(&mock_tx).with_context(|| "in from_json_str(&mock_tx)")?;
    if repr_mock_tx.tx.cell_deps.len() == 0 {
        repr_mock_tx.tx.cell_deps = repr_mock_tx
            .mock_info
            .cell_deps
            .iter()
            .map(|c| c.cell_dep.clone())
            .collect::<Vec<_>>();
    }
    if repr_mock_tx.tx.inputs.len() == 0 {
        repr_mock_tx.tx.inputs = repr_mock_tx
            .mock_info
            .inputs
            .iter()
            .map(|c| c.input.clone())
            .collect::<Vec<_>>();
    }
    Ok(repr_mock_tx)
}

pub fn create_script_from_cell_dep(
    tx: &ReprMockTransaction,
    index: usize,
    use_type: bool,
) -> Result<packed::Script, anyhow::Error> {
    assert!(index < tx.mock_info.cell_deps.len());
    let code_hash = if use_type {
        let cell_dep = &tx.mock_info.cell_deps[index];
        let script = cell_dep.output.type_.clone().unwrap();
        let script: packed::Script = script.into();
        hash(script.as_slice())
    } else {
        let data = tx.mock_info.cell_deps[index].data.as_bytes();
        hash(data)
    };
    let hash_type = if use_type {
        ScriptHashType::Type
    } else {
        ScriptHashType::Data1
    };
    let script = packed::Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();
    Ok(script)
}

// return smt root, witness args
pub fn create_simple_case(
    scripts: Vec<ChildScript>,
    witness_base_index: u8,
) -> (H256, WitnessArgs) {
    let builder = ChildScriptVec::new_builder();
    let child_scripts = builder.extend(scripts).build();

    let h = hash(child_scripts.as_slice());
    let (root, proof) = build_tree(&Vec::from([h]));

    let index = Uint16::new_builder()
        .nth0(witness_base_index.into())
        .build();
    let proof: Bytes = proof.into();
    let proof2: BlockchainBytes = proof.pack();
    let combine_lock_witness = CombineLockWitness::new_builder()
        .scripts(child_scripts)
        .proof(proof2)
        .witness_base_index(index)
        .build();
    let bytes = combine_lock_witness.as_bytes();
    let witness_args = WitnessArgs::new_builder().lock(Some(bytes).pack()).build();

    (root, witness_args)
}

impl From<packed::Script> for ChildScript {
    fn from(value: packed::Script) -> Self {
        ChildScript::new_unchecked(value.as_bytes())
    }
}

impl From<ChildScript> for packed::Script {
    fn from(value: ChildScript) -> Self {
        packed::Script::new_unchecked(value.as_bytes())
    }
}

// Now, only support lock script
fn get_group(index: usize, repr_tx: &ReprMockTransaction) -> Vec<usize> {
    let lock = repr_tx.mock_info.inputs[index].output.lock.clone();
    let mut result = vec![];
    for (i, x) in repr_tx.mock_info.inputs.iter().enumerate() {
        if lock == x.output.lock {
            result.push(i);
        }
    }
    result
}

pub fn generate_sighash_all(
    tx: &ReprMockTransaction,
    index: usize,
) -> Result<[u8; 32], anyhow::Error> {
    let lock_indexs = get_group(index, &tx);
    if lock_indexs.is_empty() {
        panic!("not get lock index");
    }

    let witness = tx
        .tx
        .witnesses
        .get(lock_indexs[0])
        .unwrap()
        .as_bytes()
        .to_vec();
    let witness = packed::WitnessArgs::new_unchecked(Bytes::from(witness));

    let witness = packed::WitnessArgsBuilder::default()
        .lock({
            let data = witness.lock().to_opt().unwrap();

            let mut buf = Vec::new();
            buf.resize(data.len(), 0);
            Some(Bytes::from(buf)).pack()
        })
        .input_type(witness.input_type())
        .output_type(witness.output_type())
        .build();

    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];

    let mock_tx: MockTransaction = tx.clone().into();

    let tx_hash = mock_tx.tx.calc_tx_hash();
    blake2b.update(&tx_hash.raw_data());
    // println!("--hash: {:02X?}", &tx_hash.raw_data().to_vec());
    let witness_data = witness.as_bytes();
    blake2b.update(&(witness_data.len() as u64).to_le_bytes());
    blake2b.update(&witness_data);

    // group
    if lock_indexs.len() > 1 {
        for i in 1..lock_indexs.len() {
            let witness = mock_tx.tx.witnesses().get(lock_indexs[i]).unwrap();

            blake2b.update(&(witness.len() as u64).to_le_bytes());
            blake2b.update(&witness.raw_data());
        }
    }

    let normal_witness_len = std::cmp::max(tx.tx.inputs.len(), tx.tx.outputs.len());
    if tx.tx.inputs.len() < normal_witness_len {
        for i in tx.tx.inputs.len()..normal_witness_len {
            let witness = mock_tx.tx.witnesses().get(i).unwrap();

            blake2b.update(&(witness.len() as u64).to_le_bytes());
            blake2b.update(&witness.raw_data());
        }
    }

    blake2b.finalize(&mut message);
    Ok(message)
}
