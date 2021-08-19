#![allow(unused_imports)]
#![allow(dead_code)]


use std::convert::From;
use log::{debug};
use std::sync::Once;

use std::collections::HashMap;
use secp256k1::schnorrsig::{KeyPair, PublicKey};
use secp256k1::{SecretKey, Secp256k1, Message};

use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
use ckb_error::Error;
use ckb_hash::{Blake2b, Blake2bBuilder};
use ckb_script::TxVerifyEnv;
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::bytes::{BufMut, BytesMut};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        hardfork::HardForkSwitch,
        Capacity, DepType, EpochNumberWithFraction, HeaderView, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    molecule,
    packed::{
        self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs,
        WitnessArgsBuilder,
    },
    prelude::*,
    H256 as CkbH256,
};
use lazy_static::lazy_static;
use rand::prelude::{thread_rng, ThreadRng};
use rand::Rng;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Hasher;
use sparse_merkle_tree::{SparseMerkleTree, H256};

use taproot_lock_test::taproot_lock::TaprootLockWitnessLock;

pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;

// errors
pub const ERROR_ENCODING: i8 = -2;

lazy_static! {
    pub static ref TAPROOT_LOCK: Bytes =
        Bytes::from(&include_bytes!("../../../build/taproot_lock")[..]);
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../build/secp256k1_data_20210801")[..]);
    pub static ref ALWAYS_SUCCESS: Bytes =
        Bytes::from(&include_bytes!("../../../build/always_success")[..]);
    pub static ref SMT_EXISTING: H256 = H256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
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
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
}

pub type SMT = SparseMerkleTree<CKBBlake2bHasher, H256, DefaultStore<H256>>;

pub fn new_smt(pairs: Vec<(H256, H256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}


pub const IDENTITY_FLAGS_SCHNORR: u8 = 6;

#[derive(Clone)]
pub struct Identity {
    pub flags: u8,
    pub blake160: Bytes,
}

impl From<Identity> for [u8; 21] {
    fn from(id: Identity) -> Self {
        let mut res = [0u8; 21];
        res[0] = id.flags;
        res[1..].copy_from_slice(&id.blake160);
        res
    }
}

impl From<Identity> for Bytes {
    fn from(id: Identity) -> Self {
        let mut bytes = BytesMut::with_capacity(128);
        bytes.put_u8(id.flags);
        bytes.put(id.blake160.as_ref());
        bytes.freeze()
    }
}

pub struct TestConfig {
    pub id: Identity,
    pub scheme: TestScheme,
    pub scheme2: TestScheme2,
    pub smt_root: Bytes,
    pub smt_proof: Bytes,
    pub key_pair: KeyPair,
    pub pubkey: PublicKey,
}

#[derive(Copy, Clone, PartialEq)]
pub enum TestScheme {
    None,
    LongWitness,

    OnWhiteList,
    NotOnWhiteList,
    OnlyInputOnWhiteList,
    OnlyOutputOnWhiteList,
    BothOnWhiteList,
    OnBlackList,
    NotOnBlackList,
    BothOn,
    EmergencyHaltMode,
}

#[derive(Copy, Clone, PartialEq)]
pub enum TestScheme2 {
    None,
    NoWitness,
}

static INIT_LOGGER: Once = Once::new();

fn setup() {
    INIT_LOGGER.call_once(|| {
        env_logger::init();
    });
}

impl TestConfig {
    pub fn new() -> TestConfig {
        setup();
        let flags = IDENTITY_FLAGS_SCHNORR;
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("secret key");

        let key_pair = KeyPair::from_secret_key(&secp, secret_key);
        let pubkey = PublicKey::from_keypair(&secp, &key_pair);

        let blake160 = blake160(&pubkey.serialize()[..]);
        TestConfig {
            id: Identity { flags, blake160 },
            smt_root: Default::default(),
            smt_proof: Default::default(),
            scheme: TestScheme::None,
            scheme2: TestScheme2::None,
            key_pair,
            pubkey,
        }
    }

    pub fn set_scheme(&mut self, scheme: TestScheme) {
        self.scheme = scheme;
    }
    pub fn gen_args(&self) -> Bytes {
        self.id.clone().into()
    }
}

pub fn gen_random_out_point(rng: &mut ThreadRng) -> OutPoint {
    let hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        Pack::pack(&buf)
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
    let capacity = bin.len() as u64;
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
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

// return smt root and proof
fn build_smt_on_wl(hashes: &Vec<[u8; 32]>, on: bool) -> (H256, Vec<u8>) {
    let existing_pairs: Vec<(H256, H256)> = hashes
        .clone()
        .into_iter()
        .map(|hash| (hash.into(), SMT_EXISTING.clone()))
        .collect();

    // this is the hash on white list, and "hashes" are on that.
    let key_on_wl1: H256 = [
        111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let key_on_wl2: H256 = [
        222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let mut pairs = vec![
        (key_on_wl1, SMT_EXISTING.clone()),
        (key_on_wl2, SMT_EXISTING.clone()),
    ];
    if on {
        pairs.extend(existing_pairs.clone());
    }

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(existing_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .expect("gen proof");
    let compiled_proof = proof
        .clone()
        .compile(existing_pairs.clone())
        .expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(root, existing_pairs.clone())
        .expect("verify compiled proof");
    if on {
        assert!(test_on);
    } else {
        assert!(!test_on);
    }
    return (root.clone(), compiled_proof.into());
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, ckb_types::bytes::Bytes)>,
}

impl DummyDataLoader {
    pub fn new() -> Self {
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

pub fn blake160(message: &[u8]) -> Bytes {
    let r = ckb_hash::blake2b_256(message);
    Bytes::copy_from_slice(&r[..20])
}

pub fn sign_tx(
    dummy: &mut DummyDataLoader,
    tx: TransactionView,
    config: &mut TestConfig,
) -> TransactionView {
    let len = tx.witnesses().len();
    sign_tx_by_input_group(dummy, tx, 0, len, config)
}

pub fn generate_sighash_all(tx: &TransactionView, begin: usize) -> [u8; 32] {
    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    let tx_hash = tx.hash();

    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::new_unchecked(tx.witnesses().get(begin).unwrap().unpack());
    let zero_lock = gen_zero_witness_lock();

    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    let len = tx.witnesses().len();
    for n in (begin + 1)..len {
        let witness = tx.witnesses().get(n).unwrap();
        let witness_len = witness.raw_data().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness.raw_data());
    }
    blake2b.finalize(&mut message);
    message
}

pub fn sign_tx_by_input_group(
    _dummy: &mut DummyDataLoader,
    tx: TransactionView,
    begin_index: usize,
    _len: usize,
    config: &TestConfig,
) -> TransactionView {
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let secp = Secp256k1::new();

                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let message = generate_sighash_all(&tx, begin_index);
                let msg = &Message::from_slice(&message[..]).expect("from_slice");
                let sig = secp.schnorrsig_sign_no_aux_rand(msg, &config.key_pair);
                let pubkey = config.pubkey.serialize();
                debug!("msg = {:?}", &message[..4]);
                debug!("pubkey = {:?}", &pubkey[..4]);
                debug!("sig = {:?}", &sig.as_ref()[..4]);

                // schnorr signature is composed by pubkey(32 bytes) + sig(64 bytes)
                let mut sig_bytes = BytesMut::new();
                sig_bytes.put_slice(pubkey.as_ref());
                sig_bytes.put_slice(sig.as_ref());
                let witness_lock = gen_witness_lock(sig_bytes.freeze());
                witness
                    .as_builder()
                    .lock(Some(witness_lock).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn gen_tx(dummy: &mut DummyDataLoader, config: &mut TestConfig) -> TransactionView {
    let lock_args = config.gen_args();
    gen_tx_with_grouped_args(dummy, vec![(lock_args, 1)], config)
}

pub fn add_lock_script(dummy: &mut DummyDataLoader, lock_script: Script) -> OutPoint {
    let mut rng = thread_rng();
    let dummy_capacity = Capacity::shannons(42);

    let previous_tx_hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    let previous_out_point = OutPoint::new(previous_tx_hash, 0);
    let previous_output_cell = CellOutput::new_builder()
        .capacity(dummy_capacity.pack())
        .lock(lock_script)
        .build();
    dummy.cells.insert(
        previous_out_point.clone(),
        (previous_output_cell.clone(), Bytes::new()),
    );
    previous_out_point
}

pub fn gen_tx_with_grouped_args(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    config: &mut TestConfig,
) -> TransactionView {
    let mut rng = thread_rng();
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    let (b0, _) = build_script(
        dummy,
        tx_builder,
        false,
        &SECP256K1_DATA_BIN,
        Default::default(),
    );
    tx_builder = b0;

    for (args, inputs_size) in grouped_args {
        let (b0, script) = build_script(dummy, tx_builder, false, &TAPROOT_LOCK, args);
        tx_builder = b0;

        for _ in 0..inputs_size {
            let out_point = add_lock_script(dummy, script.clone());

            let mut random_extra_witness = Vec::<u8>::new();
            let witness_len = if config.scheme == TestScheme::LongWitness {
                40000
            } else {
                32
            };
            random_extra_witness.resize(witness_len, 0);
            rng.fill(&mut random_extra_witness[..]);

            let witness_args = WitnessArgsBuilder::default()
                .input_type(Some(Bytes::copy_from_slice(&random_extra_witness[..])).pack())
                .build();
            tx_builder = tx_builder
                .input(CellInput::new(out_point, 0))
                .witness(witness_args.as_bytes().pack());
        }
    }

    tx_builder.build()
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

pub fn debug_printer(script: &Byte32, msg: &str) {
    let slice = script.as_slice();
    let str = format!(
        "Script({:x}{:x}{:x}{:x}{:x})",
        slice[0], slice[1], slice[2], slice[3], slice[4]
    );
    debug!("{:?}: {}", str, msg);
}

pub fn gen_witness_lock(sig: Bytes) -> Bytes {
    let builder = TaprootLockWitnessLock::new_builder();
    let builder = builder.signature(Some(sig).pack());
    builder.build().as_bytes()
}

pub fn gen_zero_witness_lock() -> Bytes {
    let mut zero = BytesMut::new();
    zero.resize(96, 0);
    let witness_lock = gen_witness_lock(zero.freeze());

    let mut res = BytesMut::new();
    res.resize(witness_lock.len(), 0);
    res.freeze()
}

pub fn assert_script_error(err: Error, err_code: i8) {
    // For ckb 0.40.0
    // use ckb_error::assert_error_eq;
    // use ckb_script::ScriptError;
    // assert_error_eq!(
    //     err,
    //     ScriptError::ValidationFailure(err_code).input_lock_script(1)
    // );

    assert!(err
        .to_string()
        .contains(format!("error code {}", err_code).as_str()));
}

pub fn gen_consensus() -> Consensus {
    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0232(200)
        .build()
        .unwrap();
    ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build()
}

pub fn gen_tx_env() -> TxVerifyEnv {
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let header = HeaderView::new_advanced_builder()
        .epoch(epoch.pack())
        .build();
    TxVerifyEnv::new_commit(&header)
}
