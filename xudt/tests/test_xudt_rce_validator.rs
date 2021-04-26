mod misc;
use misc::{debug_printer, MAX_CYCLES};

use std::collections::HashMap;

use blake2b_rs::{Blake2b, Blake2bBuilder};
use ckb_script::TransactionScriptsVerifier;
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types;
use ckb_types::core::cell::{CellMeta, CellMetaBuilder, ResolvedTransaction};
use ckb_types::core::{
    Capacity, DepType, HeaderView, ScriptHashType, TransactionBuilder, TransactionView,
};
use ckb_types::packed::{
    Byte32, BytesOptBuilder, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgsBuilder,
};
use ckb_types::prelude::{Builder as ckbBuilder, Entity as ckbEntity, Pack};
use lazy_static::lazy_static;
use molecule::prelude::{Builder as molBuilder, Entity};
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use sparse_merkle_tree::{default_store::DefaultStore, traits::Hasher, SparseMerkleTree, H256};

use xudt::blockchain;
use xudt::xudt_rce_mol::{
    RCDataBuilder, RCDataUnion, RCRuleBuilder, SmtProofBuilder, SmtUpdateActionBuilder,
    SmtUpdateItemBuilder, SmtUpdateItemVecBuilder,
};

// on(1): white list
// off(0): black list
const WHITE_BLACK_LIST_MASK: u8 = 0x2;
// on(1): emergency halt mode
// off(0): not int emergency halt mode
const EMERGENCY_HALT_MODE_MASK: u8 = 0x1;

const BLAKE2B_KEY: &[u8] = &[];
const BLAKE2B_LEN: usize = 32;
const PERSONALIZATION: &[u8] = b"ckb-default-hash";

lazy_static! {
    pub static ref SMT_EXISTING: H256 = H256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
    pub static ref SMT_NOT_EXISTING: H256 = H256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
    pub static ref TYPE_ID_CODE_HASH: [u8; 32] = [
        0x54, 0x59, 0x50, 0x45, 0x5f, 0x49, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
    pub static ref K1: [u8; 32] = [
        111, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
    pub static ref K2: [u8; 32] = [
        222, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
}

pub struct CKBBlake2bHasher(Blake2b);
impl Default for CKBBlake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        CKBBlake2bHasher(blake2b)
    }
}

impl Hasher for CKBBlake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
}
type SMT = SparseMerkleTree<CKBBlake2bHasher, H256, DefaultStore<H256>>;

fn new_smt(pairs: Vec<(H256, H256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}

fn build_rc_rule(
    smt_root: &[u8; 32],
    is_black: bool,
    is_emergency: bool,
) -> ckb_types::bytes::Bytes {
    let mut flags: u8 = 0;

    if !is_black {
        flags ^= WHITE_BLACK_LIST_MASK;
    }
    if is_emergency {
        flags ^= EMERGENCY_HALT_MODE_MASK;
    }
    let smt_root = molecule::bytes::Bytes::from(smt_root.as_ref());
    let sr = blockchain::Byte32::new_unchecked(smt_root);
    let rcrule = RCRuleBuilder::default()
        .flags(molecule::prelude::Byte::new(flags))
        .smt_root(sr)
        .build();
    let res = RCDataBuilder::default()
        .set(RCDataUnion::RCRule(rcrule))
        .build();
    ckb_types::bytes::Bytes::copy_from_slice(res.as_slice())
}

fn gen_random_out_point(rng: &mut ThreadRng) -> OutPoint {
    let hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        Pack::pack(&buf)
    };
    OutPoint::new(hash, 0)
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, ckb_types::bytes::Bytes)>,
}

impl DummyDataLoader {
    fn new() -> Self {
        Self::default()
    }
}

impl CellDataProvider for DummyDataLoader {
    // load Cell Data
    fn load_cell_data(&self, cell: &CellMeta) -> Option<ckb_types::bytes::Bytes> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .map(|(_, data)| data.clone())
        })
    }

    fn load_cell_data_hash(&self, cell: &CellMeta) -> Option<Byte32> {
        self.load_cell_data(cell)
            .map(|e| CellOutput::calc_data_hash(&e))
    }

    fn get_cell_data(&self, _out_point: &OutPoint) -> Option<ckb_types::bytes::Bytes> {
        None
    }

    fn get_cell_data_hash(&self, _out_point: &OutPoint) -> Option<Byte32> {
        None
    }
}

impl HeaderProvider for DummyDataLoader {
    fn get_header(&self, _hash: &Byte32) -> Option<HeaderView> {
        None
    }
}

pub fn build_resolved_tx(
    data_loader: &DummyDataLoader,
    tx: &TransactionView,
) -> ResolvedTransaction {
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|dep| {
            let deps_out_point = dep.clone();
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point().clone())
                .build()
        })
        .collect();

    let mut resolved_inputs = Vec::new();
    for i in 0..tx.inputs().len() {
        let previous_out_point = tx.inputs().get(i).unwrap().previous_output();
        let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
        resolved_inputs.push(
            CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
                .out_point(previous_out_point)
                .build(),
        );
    }

    ResolvedTransaction {
        transaction: tx.clone(),
        resolved_cell_deps,
        resolved_inputs,
        resolved_dep_groups: vec![],
    }
}

#[test]
fn test_rce_validator_no_input() {
    let old_smt_keys = vec![];
    let new_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let mod_keys = vec![(H256::from(K1.clone()), SMT_NOT_EXISTING.clone())];
    let packed_values = 0b0000_0001;
    let flag = 0;

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let old_smt_root = old_smt.root().clone();
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys.clone()).unwrap();
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    let smt_update_item = SmtUpdateItemBuilder::default()
        .key(blockchain::Byte32::from_slice(&K1.clone()).unwrap())
        .packed_values(packed_values.into())
        .build();
    let smt_update_item_vec = SmtUpdateItemVecBuilder::default()
        .push(smt_update_item)
        .build();
    let smt_proof = SmtProofBuilder::default()
        .set(
            merkle_proof_bytes
                .into_iter()
                .map(|v| molecule::prelude::Byte::new(v))
                .collect(),
        )
        .build();
    let smt_update_action = SmtUpdateActionBuilder::default()
        .updates(smt_update_item_vec)
        .proof(smt_proof)
        .build();
    let smt_update_action_bytes = smt_update_action.as_slice();

    let witness_args = WitnessArgsBuilder::default()
        .input_type(
            BytesOptBuilder::default()
                .set(Some(Pack::pack(&ckb_types::bytes::Bytes::copy_from_slice(
                    smt_update_action_bytes,
                ))))
                .build(),
        )
        .build();
    let witness_args_bytes = witness_args.as_slice();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes =
        ckb_types::bytes::Bytes::from(include_bytes!("../../build/always_success").as_ref());
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = ckb_types::bytes::Bytes::copy_from_slice(
        build_rc_rule(&old_smt_root.into(), true, false).as_ref(),
    );
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .build();

    let old_rce_cell_hash = {
        let mut blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        blake2b.update(CellInput::new(old_rce_out_point.clone(), 0).as_slice());
        blake2b.update(&0u64.to_le_bytes());
        let mut ret = [0; 32];
        blake2b.finalize(&mut ret);
        ckb_types::bytes::Bytes::from(ret.to_vec())
    };

    let rce_validator_cell_data: ckb_types::bytes::Bytes =
        ckb_types::bytes::Bytes::from(include_bytes!("../../build/rce_validator").as_ref());
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&old_rce_cell_hash[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = ckb_types::bytes::Bytes::copy_from_slice(
        build_rc_rule(&new_smt_root.into(), true, false).as_ref(),
    );

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .witness(ckb_types::bytes::Bytes::copy_from_slice(witness_args_bytes.clone()).pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert!(r.is_ok())
}
