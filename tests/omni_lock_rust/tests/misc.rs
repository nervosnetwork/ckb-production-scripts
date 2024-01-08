use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::convert::TryInto;

use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
use ckb_crypto::secp::{Generator, Privkey, Pubkey};
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
use rand::seq::SliceRandom;
use rand::Rng;
use rand::RngCore;

use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Hasher;
use sparse_merkle_tree::{SparseMerkleTree, H256};

use omni_lock_test::omni_lock;
use omni_lock_test::omni_lock::OmniLockWitnessLock;
use omni_lock_test::xudt_rce_mol::{
    RCCellVecBuilder, RCDataBuilder, RCDataUnion, RCRuleBuilder, SmtProofBuilder,
    SmtProofEntryBuilder, SmtProofEntryVec, SmtProofEntryVecBuilder,
};

// on(1): white list
// off(0): black list
pub const WHITE_BLACK_LIST_MASK: u8 = 0x2;
// on(1): emergency halt mode
// off(0): not int emergency halt mode
pub const EMERGENCY_HALT_MODE_MASK: u8 = 0x1;

pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;

// errors
pub const CKB_INVALID_DATA: i8 = 4;
pub const ERROR_ENCODING: i8 = -2;
pub const ERROR_WITNESS_SIZE: i8 = -22;
pub const ERROR_PUBKEY_BLAKE160_HASH: i8 = -31;
pub const ERROR_OUTPUT_AMOUNT_NOT_ENOUGH: i8 = -42;
pub const ERROR_NO_PAIR: i8 = -44;
pub const ERROR_DUPLICATED_INPUTS: i8 = -45;
pub const ERROR_DUPLICATED_OUTPUTS: i8 = -46;
pub const ERROR_LOCK_SCRIPT_HASH_NOT_FOUND: i8 = 70;
pub const ERROR_NOT_ON_WHITE_LIST: i8 = 59;
pub const ERROR_NO_WHITE_LIST: i8 = 83;
pub const ERROR_ON_BLACK_LIST: i8 = 57;
pub const ERROR_RCE_EMERGENCY_HALT: i8 = 54;
pub const ERROR_RSA_VERIFY_FAILED: i8 = 42;
pub const ERROR_INCORRECT_SINCE_VALUE: i8 = -24;
pub const ERROR_ISO97962_INVALID_ARG9: i8 = 61;
// sudt supply errors
pub const ERROR_EXCEED_SUPPLY: i8 = 90;
pub const ERROR_SUPPLY_AMOUNT: i8 = 91;
pub const ERROR_BURN: i8 = 92;
pub const ERROR_NO_INFO_CELL: i8 = 93;

lazy_static! {
    pub static ref OMNI_LOCK: Bytes = Bytes::from(&include_bytes!("../../../build/omni_lock")[..]);
    pub static ref SIMPLE_UDT: Bytes =
        Bytes::from(&include_bytes!("../../../build/simple_udt")[..]);
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../build/secp256k1_data_20210801")[..]);
    pub static ref ALWAYS_SUCCESS: Bytes =
        Bytes::from(&include_bytes!("../../../build/always_success")[..]);
    pub static ref VALIDATE_SIGNATURE_RSA: Bytes =
        Bytes::from(&include_bytes!("../../../build/validate_signature_rsa")[..]);
    pub static ref SMT_EXISTING: H256 = H256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
    pub static ref SMT_NOT_EXISTING: H256 = H256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
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
// when in_input_cell is on, the cell is not in deps but in input.
fn build_script(
    dummy: &mut DummyDataLoader,
    tx_builder: TransactionBuilder,
    is_type: bool,
    in_input_cell: bool,
    bin: &Bytes,
    args: Bytes,
) -> (TransactionBuilder, Script) {
    // this hash to make type script in code unique
    // then make "type script hash" unique, which will be code_hash in "type script"
    let hash = ckb_hash::blake2b_256(bin);
    let always_success = build_always_success_script();

    let type_script_in_code = {
        if in_input_cell {
            let hash: Bytes = Bytes::copy_from_slice(&hash);
            always_success
                .clone()
                .as_builder()
                .args(hash.pack())
                .build()
        } else {
            // this args can be anything
            let args = vec![0u8; 32];
            Script::new_builder()
                .args(args.pack())
                .code_hash(hash.pack())
                .hash_type(ScriptHashType::Type.into())
                .build()
        }
    };

    // it not needed to set "type script" when is_type is false
    let capacity = bin.len() as u64;
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(always_success)
        .type_(Some(type_script_in_code.clone()).pack())
        .build();

    // use "code" hash as out point, which is unique
    let out_point = &OutPoint::new(hash.pack(), 0);

    dummy.cells.insert(out_point.clone(), (cell, bin.clone()));

    let tx_builder = if in_input_cell {
        let witness_args = WitnessArgsBuilder::default().build();
        tx_builder
            .input(CellInput::new(out_point.clone(), 0))
            .witness(witness_args.as_bytes().pack())
    } else {
        tx_builder.cell_dep(
            CellDep::new_builder()
                .out_point(out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
    };

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
fn build_smt_on_bl(hashes: &Vec<[u8; 32]>, on: bool) -> (H256, Vec<u8>) {
    let test_pairs: Vec<(H256, H256)> = hashes
        .clone()
        .into_iter()
        .map(|hash| (hash.into(), SMT_NOT_EXISTING.clone()))
        .collect();
    // this is the hash on black list, but "hashes" are not on that.
    let key_on_bl1: H256 = [
        111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let key_on_bl2: H256 = [
        222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let pairs = vec![
        (key_on_bl1, SMT_EXISTING.clone()),
        (key_on_bl2, SMT_EXISTING.clone()),
    ];
    let smt = new_smt(pairs.clone());
    let root = smt.root();

    let proof = smt
        .merkle_proof(test_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .expect("gen proof");
    let compiled_proof = proof
        .clone()
        .compile(test_pairs.clone())
        .expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(smt.root(), test_pairs.clone())
        .expect("verify compiled proof");
    assert!(test_on);
    if on {
        let mut new_root = root.clone();
        let one = new_root.get_bit(0);
        if one {
            new_root.clear_bit(0);
        } else {
            new_root.set_bit(0);
        }
        (new_root.clone(), compiled_proof.into())
    } else {
        (root.clone(), compiled_proof.into())
    }
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

fn build_rc_rule(smt_root: &[u8; 32], is_black: bool, is_emergency: bool) -> Bytes {
    let mut flags: u8 = 0;

    if !is_black {
        flags ^= WHITE_BLACK_LIST_MASK;
    }
    if is_emergency {
        flags ^= EMERGENCY_HALT_MODE_MASK;
    }
    let rcrule = RCRuleBuilder::default()
        .flags(flags.into())
        .smt_root(smt_root.pack())
        .build();
    let res = RCDataBuilder::default()
        .set(RCDataUnion::RCRule(rcrule))
        .build();
    res.as_bytes()
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

pub fn keccak160(message: &[u8]) -> Bytes {
    let mut hasher = Keccak256::new();
    hasher.update(message);
    let r = hasher.finalize();
    Bytes::copy_from_slice(&r[12..])
}

pub fn convert_keccak256_hash(message: &[u8]) -> CkbH256 {
    let eth_prefix: &[u8; 28] = b"\x19Ethereum Signed Message:\n32";
    let mut hasher = Keccak256::new();
    hasher.update(eth_prefix);
    hasher.update(message);
    let r = hasher.finalize();
    CkbH256::from_slice(r.as_slice()).expect("convert_keccak256_hash")
}

pub fn sign_tx(
    dummy: &mut DummyDataLoader,
    tx: TransactionView,
    config: &mut TestConfig,
) -> TransactionView {
    // for owner lock, the first input is an "always success" script: used as owner lock
    let (begin_index, witnesses_len) = if config.is_owner_lock() {
        (1, tx.witnesses().len() - 1)
    } else {
        (
            config.leading_witness_count,
            tx.witnesses().len() - config.leading_witness_count,
        )
    };
    sign_tx_by_input_group(dummy, tx, begin_index, witnesses_len, config)
}

fn build_proofs(proofs: Vec<Vec<u8>>, proof_masks: Vec<u8>) -> SmtProofEntryVec {
    assert_eq!(proofs.len(), proof_masks.len());

    let mut builder = SmtProofEntryVecBuilder::default();
    let iter = proofs.iter().zip(proof_masks.iter());
    for (p, m) in iter {
        let proof_builder = SmtProofBuilder::default().set(
            p.into_iter()
                .map(|v| molecule::prelude::Byte::new(*v))
                .collect(),
        );

        let temp = SmtProofEntryBuilder::default()
            .proof(proof_builder.build())
            .mask((*m).into());
        builder = builder.push(temp.build());
    }
    builder.build()
}

pub fn build_always_success_script() -> Script {
    let data_hash = CellOutput::calc_data_hash(&ALWAYS_SUCCESS);
    Script::new_builder()
        .code_hash(data_hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .build()
}

pub fn build_omni_lock_script(config: &mut TestConfig, args: Bytes) -> Script {
    let args = if config.is_owner_lock() {
        if config.scheme == TestScheme::OwnerLockMismatched {
            config.id.blake160 = {
                let mut buf = BytesMut::new();
                buf.resize(20, 0);
                buf.freeze()
            };
            config.gen_args()
        } else {
            config.gen_args()
        }
    } else {
        if config.is_rc() {
            config.gen_args()
        } else {
            args
        }
    };
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&OMNI_LOCK);
    Script::new_builder()
        .args(args.pack())
        .code_hash(sighash_all_cell_data_hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .build()
}

pub fn append_rc(
    dummy: &mut DummyDataLoader,
    tx_builder: TransactionBuilder,
    config: &mut TestConfig,
) -> TransactionBuilder {
    let smt_key = config.id.to_smt_key();
    let (proofs, rc_datas, proof_masks) = generate_proofs(config.scheme, &vec![smt_key]);
    let (rc_root, b0) = generate_rce_cell(dummy, tx_builder, rc_datas, config.smt_in_input);

    config.proofs = proofs;
    config.proof_masks = proof_masks;
    config.rc_root = rc_root.as_bytes();
    if config.smt_in_input {
        // one is RCCellVec, one is RCRule
        config.leading_witness_count = 2;
    }
    b0
}

// when adding the input lock script as first one,
// it will affect witness offset and length.
pub fn append_input_lock_script_hash(
    dummy: &mut DummyDataLoader,
    tx_builder: TransactionBuilder,
) -> (TransactionBuilder, Bytes) {
    let mut rng = thread_rng();
    let previous_tx_hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    let previous_out_point = OutPoint::new(previous_tx_hash, 0);

    let hash = CellOutput::calc_data_hash(&ALWAYS_SUCCESS);
    let script = Script::new_builder()
        .args(Default::default())
        .code_hash(hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let blake160 = {
        let hash = script.calc_script_hash();
        let mut res = BytesMut::new();
        res.put(&hash.as_slice()[0..20]);
        res.freeze()
    };

    let previous_output_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(42).pack())
        .lock(script)
        .build();
    dummy.cells.insert(
        previous_out_point.clone(),
        (previous_output_cell.clone(), Bytes::new()),
    );
    let tx_builder = tx_builder
        .input(CellInput::new(previous_out_point, 0))
        .witness(Default::default());

    (tx_builder, blake160)
}

// loop through all input cell's lock script,
// check if its args's first byte is "flags", then replace the following
// 20 bytes with preimage's hash
pub fn write_back_preimage_hash(dummy: &mut DummyDataLoader, flags: u8, hash: Bytes) {
    dummy.cells = dummy
        .cells
        .clone()
        .into_iter()
        .map(|(k, (mut cell, data))| {
            let script = cell.lock();
            let args = script.args();
            if args.len() >= 21 {
                let raw = args.raw_data();
                if raw[0] == flags {
                    let mut new_args = Vec::from(raw.as_ref());
                    new_args[1..21].copy_from_slice(hash.as_ref());
                    let new_script = script
                        .as_builder()
                        .args(Bytes::from(new_args).pack())
                        .build();
                    cell = cell.as_builder().lock(new_script).build();
                }
            }
            (k, (cell, data))
        })
        .collect();
}

pub fn sign_tx_by_input_group(
    dummy: &mut DummyDataLoader,
    tx: TransactionView,
    begin_index: usize,
    len: usize,
    config: &TestConfig,
) -> TransactionView {
    let proof_vec = build_proofs(config.proofs.clone(), config.proof_masks.clone());
    let identity = config.id.to_identity();
    let tx_hash = tx.hash();
    let mut preimage_hash: Bytes = Default::default();

    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock = gen_zero_witness_lock(
                    config.use_rc,
                    config.use_rc_identity,
                    &proof_vec,
                    &identity,
                    config.sig_len,
                    config.preimage_len,
                );

                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);

                let message = if config.id.flags == IDENTITY_FLAGS_ETHEREUM {
                    convert_keccak256_hash(&message)
                } else if config.id.flags == IDENTITY_FLAGS_EOS {
                    assert!(config.eos.is_some());
                    config.eos.as_ref().unwrap().convert_message(&message)
                } else if config.id.flags == IDENTITY_FLAGS_TRON {
                    assert!(config.tron.is_some());
                    config.tron.as_ref().unwrap().convert_message(&message)
                } else if config.id.flags == IDENTITY_FLAGS_BITCOIN {
                    assert!(config.bitcoin.is_some());
                    config.bitcoin.as_ref().unwrap().convert_message(&message)
                } else if config.id.flags == IDENTITY_FLAGS_DOGECOIN {
                    assert!(config.dogecoin.is_some());
                    config.dogecoin.as_ref().unwrap().convert_message(&message)
                } else {
                    CkbH256::from(message)
                };

                let witness_lock = if config.id.flags == IDENTITY_FLAGS_DL {
                    let (mut sig, pubkey) = if config.use_rsa {
                        rsa_sign(message.as_bytes(), &config.rsa_private_key)
                    } else {
                        if config.use_iso9796_2 {
                            iso9796_2_batch_sign(message.as_bytes(), &config.rsa_private_key)
                        } else {
                            (Default::default(), Default::default())
                        }
                    };
                    if config.scheme == TestScheme::RsaWrongSignature {
                        let mut wrong_sig = sig.clone();
                        let last_index = wrong_sig.len() - 1;
                        wrong_sig[last_index] ^= 0x01;
                        sig = wrong_sig;
                    }
                    let hash = blake160(pubkey.as_ref());
                    let preimage = gen_exec_preimage(&config.rsa_script, &hash);
                    preimage_hash = blake160(preimage.as_ref());

                    let sig_bytes = Bytes::from(sig);
                    gen_witness_lock(
                        sig_bytes,
                        config.use_rc,
                        config.use_rc_identity,
                        &proof_vec,
                        &identity,
                        Some(preimage),
                    )
                } else if config.id.flags == IDENTITY_FLAGS_MULTISIG {
                    let sig = config.multisig.sign(&message.into());
                    gen_witness_lock(
                        sig,
                        config.use_rc,
                        config.use_rc_identity,
                        &proof_vec,
                        &identity,
                        None,
                    )
                } else if config.id.flags == IDENTITY_FLAGS_EOS {
                    let sig_bytes = config
                        .eos
                        .as_ref()
                        .unwrap()
                        .sign(&config.private_key, message);
                    gen_witness_lock(
                        sig_bytes,
                        config.use_rc,
                        config.use_rc_identity,
                        &proof_vec,
                        &identity,
                        None,
                    )
                } else if config.id.flags == IDENTITY_FLAGS_BITCOIN {
                    let sig_bytes = config
                        .bitcoin
                        .as_ref()
                        .unwrap()
                        .sign(&config.private_key, message);
                    gen_witness_lock(
                        sig_bytes,
                        config.use_rc,
                        config.use_rc_identity,
                        &proof_vec,
                        &identity,
                        None,
                    )
                } else if config.id.flags == IDENTITY_FLAGS_DOGECOIN {
                    let sig_bytes = config
                        .dogecoin
                        .as_ref()
                        .unwrap()
                        .sign(&config.private_key, message);
                    gen_witness_lock(
                        sig_bytes,
                        config.use_rc,
                        config.use_rc_identity,
                        &proof_vec,
                        &identity,
                        None,
                    )
                } else {
                    let sig = config.private_key.sign_recoverable(&message).expect("sign");
                    let sig_bytes = Bytes::from(sig.serialize());
                    gen_witness_lock(
                        sig_bytes,
                        config.use_rc,
                        config.use_rc_identity,
                        &proof_vec,
                        &identity,
                        None,
                    )
                };

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
    if config.scheme2 == TestScheme2::NoWitness {
        signed_witnesses.clear();
    }
    if preimage_hash.len() == 20 {
        write_back_preimage_hash(dummy, IDENTITY_FLAGS_DL, preimage_hash);
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

pub fn gen_tx_with_grouped_args(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    config: &mut TestConfig,
) -> TransactionView {
    let mut rng = thread_rng();
    // setup sighash_all dep
    let sighash_all_out_point = {
        let contract_tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(contract_tx_hash.clone(), 0)
    };
    // dep contract code
    let sighash_all_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(OMNI_LOCK.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&OMNI_LOCK);
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (sighash_all_cell, OMNI_LOCK.clone()),
    );
    // always success
    let always_success_out_point = {
        let contract_tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(contract_tx_hash.clone(), 0)
    };
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(ALWAYS_SUCCESS.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, ALWAYS_SUCCESS.clone()),
    );
    // setup secp256k1_data dep
    let secp256k1_data_out_point = {
        let tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(tx_hash, 0)
    };
    let secp256k1_data_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(SECP256K1_DATA_BIN.len())
                .expect("data capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        secp256k1_data_out_point.clone(),
        (secp256k1_data_cell, SECP256K1_DATA_BIN.clone()),
    );
    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_all_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp256k1_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    // validate_signature_rsa will be referenced by preimage in witness
    let (b0, rsa_script) = build_script(
        dummy,
        tx_builder,
        false,
        false,
        &VALIDATE_SIGNATURE_RSA,
        Default::default(),
    );
    tx_builder = b0;
    config.rsa_script = rsa_script;

    if config.is_owner_lock() {
        // insert an "always success" script as first input script.
        let (b0, blake160) = append_input_lock_script_hash(dummy, tx_builder);
        tx_builder = b0;
        config.id.blake160 = blake160;
    }
    if config.is_rc() {
        tx_builder = append_rc(dummy, tx_builder, config);
    }

    for (mut args, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let previous_tx_hash = {
                let mut buf = [0u8; 32];
                rng.fill(&mut buf);
                buf.pack()
            };
            args = if config.is_owner_lock() {
                if config.scheme == TestScheme::OwnerLockMismatched {
                    config.id.blake160 = {
                        let mut buf = BytesMut::new();
                        buf.resize(20, 0);
                        buf.freeze()
                    };
                    config.gen_args()
                } else {
                    config.gen_args()
                }
            } else {
                if config.is_rc() {
                    config.gen_args()
                } else {
                    args
                }
            };
            let previous_out_point = OutPoint::new(previous_tx_hash, 0);
            let script = Script::new_builder()
                .args(args.pack())
                .code_hash(sighash_all_cell_data_hash.clone())
                .hash_type(ScriptHashType::Data.into())
                .build();
            config.running_script = script.clone();
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script)
                .build();
            dummy.cells.insert(
                previous_out_point.clone(),
                (previous_output_cell.clone(), Bytes::new()),
            );
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
            let since = if config.use_since {
                config.input_since
            } else {
                0
            };
            tx_builder = tx_builder
                .input(CellInput::new(previous_out_point, since))
                .witness(witness_args.as_bytes().pack());
        }
    }

    tx_builder.build()
}

pub fn sign_tx_hash(tx: TransactionView, tx_hash: &[u8], config: &TestConfig) -> TransactionView {
    let identity = config.id.to_identity();
    // calculate message
    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(tx_hash);
    blake2b.finalize(&mut message);
    let message = CkbH256::from(message);
    let sig = config.private_key.sign_recoverable(&message).expect("sign");
    let proofs = SmtProofEntryVecBuilder::default().build();
    let witness_lock = gen_witness_lock(
        sig.serialize().into(),
        config.use_rc,
        config.use_rc_identity,
        &proofs,
        &identity,
        Default::default(),
    );
    let witness_args = WitnessArgsBuilder::default()
        .lock(Some(witness_lock).pack())
        .build();
    tx.as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build()
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
    println!("{:?}: {}", str, msg);
}

pub const IDENTITY_FLAGS_PUBKEY_HASH: u8 = 0;
pub const IDENTITY_FLAGS_ETHEREUM: u8 = 1;
pub const IDENTITY_FLAGS_EOS: u8 = 2;
pub const IDENTITY_FLAGS_TRON: u8 = 3;
pub const IDENTITY_FLAGS_BITCOIN: u8 = 4;
pub const IDENTITY_FLAGS_DOGECOIN: u8 = 5;
pub const IDENTITY_FLAGS_MULTISIG: u8 = 6;

pub const IDENTITY_FLAGS_OWNER_LOCK: u8 = 0xFC;
pub const IDENTITY_FLAGS_EXEC: u8 = 0xFD;
pub const IDENTITY_FLAGS_DL: u8 = 0xFE;

pub struct Identity {
    pub flags: u8,
    pub blake160: Bytes,
}

impl Identity {
    pub fn to_smt_key(&self) -> [u8; 32] {
        let mut ret: [u8; 32] = Default::default();
        ret[0] = self.flags;
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        ret
    }
    pub fn to_identity(&self) -> omni_lock::Auth {
        let mut ret: [u8; 21] = Default::default();
        ret[0] = self.flags;
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        omni_lock::Auth::from_slice(&ret[..]).unwrap()
    }
}

pub struct MultisigTestConfig {
    pub private_keys: Vec<Privkey>,
    pub pubkeys: Vec<Pubkey>,
    pub require_first_n: u8,
    pub threshold: u8,
    pub count: u8,
}

impl MultisigTestConfig {
    pub fn set(&mut self, require_first_n: u8, threshold: u8, count: u8) {
        let mut private_keys: Vec<Privkey> = vec![];
        let mut pubkeys: Vec<Pubkey> = vec![];
        for _ in 0..count {
            let p = Generator::random_privkey();
            pubkeys.push(p.pubkey().expect("pubkey"));
            private_keys.push(p);
        }
        self.private_keys = private_keys;
        self.pubkeys = pubkeys;
        self.require_first_n = require_first_n;
        self.threshold = threshold;
        self.count = count;
    }

    fn gen_multisig_script(&self) -> Bytes {
        let mut result = BytesMut::new();
        result.put_u8(0);
        result.put_u8(self.require_first_n);
        result.put_u8(self.threshold);
        result.put_u8(self.count);

        for p in &self.pubkeys {
            result.put_slice(&blake160(&p.serialize()));
        }

        result.freeze()
    }
    fn sign(&self, msg: &CkbH256) -> Bytes {
        // println!("message = {:?}", msg);
        let mut result = BytesMut::new();
        // let sig = config.private_key.sign_recoverable(&message).expect("sign");
        // let sig_bytes = Bytes::from(sig.serialize());
        let multisig_script = self.gen_multisig_script();
        result.put_slice(&multisig_script);

        // require first N
        let mut private_keys = self.private_keys.clone();
        if self.require_first_n > 0 {
            for i in 0..self.require_first_n as usize {
                let sig = private_keys[i].sign_recoverable(msg).expect("sign");
                result.put_slice(&sig.serialize());
            }
            for _ in 0..self.require_first_n {
                private_keys.remove(0);
            }
        }
        let remaining_threshold: usize = self.threshold as usize - self.require_first_n as usize;

        // remaining with random order
        private_keys.shuffle(&mut thread_rng());

        for privkey in &private_keys[0..remaining_threshold] {
            let sig = privkey.sign_recoverable(msg).expect("sign");
            result.put_slice(&sig.serialize());
        }
        result.freeze()
    }

    pub fn gen_identity(&self) -> Identity {
        let script = self.gen_multisig_script();
        Identity {
            flags: IDENTITY_FLAGS_MULTISIG,
            blake160: blake160(&script),
        }
    }
}

impl Default for MultisigTestConfig {
    fn default() -> Self {
        MultisigTestConfig {
            private_keys: Default::default(),
            pubkeys: Default::default(),
            require_first_n: 0,
            threshold: 0,
            count: 0,
        }
    }
}

pub const BITCOIN_V_TYPE_P2PKHUNCOMPRESSED: u8 = 27;
pub const BITCOIN_V_TYPE_P2PKHCOMPRESSED: u8 = 31;
pub const BITCOIN_V_TYPE_SEGWITP2SH: u8 = 35;
pub const BITCOIN_V_TYPE_SEGWITBECH32: u8 = 39;

pub struct BitcoinConfig {
    pub sign_vtype: u8,
    pub pubkey_err: bool,
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
            pubkey_err: false,
        }
    }
}

impl BitcoinConfig {
    pub fn get_pubkey_hash(&self, pubkey: &Pubkey) -> [u8; 20] {
        if self.pubkey_err {
            let mut r = [0u8; 20];
            thread_rng().fill_bytes(&mut r);
            return r;
        }
        match self.sign_vtype {
            BITCOIN_V_TYPE_P2PKHUNCOMPRESSED => {
                let mut pk_data = Vec::<u8>::new();
                pk_data.resize(65, 0);
                pk_data[0] = 4;
                pk_data[1..].copy_from_slice(pubkey.as_bytes());

                bitcoin_hash160(&pk_data)
            }
            BITCOIN_V_TYPE_P2PKHCOMPRESSED => bitcoin_hash160(&pubkey.serialize()),
            BITCOIN_V_TYPE_SEGWITP2SH => {
                // Ripemd160(Sha256([00, 20, Ripemd160(Sha256(Compressed Public key))]))

                let mut buf = Vec::<u8>::new();
                buf.resize(22, 0);
                buf[0] = 0;
                buf[1] = 20;
                buf[2..].copy_from_slice(&bitcoin_hash160(&pubkey.serialize()));
                bitcoin_hash160(&buf)
            }
            BITCOIN_V_TYPE_SEGWITBECH32 => bitcoin_hash160(&pubkey.serialize()),
            _ => {
                panic!("unknow sign_vtype")
            }
        }
    }

    pub fn convert_message(&self, message: &[u8; 32]) -> CkbH256 {
        let message_magic = b"\x18Bitcoin Signed Message:\n\x40";
        let msg_hex = hex::encode(message);
        assert_eq!(msg_hex.len(), 64);

        let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
        temp2.put(Bytes::from(message_magic.to_vec()));
        temp2.put(Bytes::from(hex::encode(message)));

        let msg = calculate_sha256(&temp2.to_vec());
        let msg = calculate_sha256(&msg);

        CkbH256::from(msg)
    }

    pub fn sign(&self, privkey: &Privkey, message: CkbH256) -> Bytes {
        let sign = privkey
            .sign_recoverable(&message)
            .expect("sign secp256k1")
            .serialize();
        let recid = sign[64];

        let mark = recid + self.sign_vtype;

        let mut ret = BytesMut::with_capacity(65);
        ret.put_u8(mark);
        ret.put(&sign[0..64]);
        Bytes::from(ret)
    }
}

#[derive(Default)]
pub struct DogecoinConfig(pub BitcoinConfig);

impl DogecoinConfig {
    pub fn get_pubkey_hash(&self, pubkey: &Pubkey) -> [u8; 20] {
        self.0.get_pubkey_hash(pubkey)
    }

    pub fn convert_message(&self, message: &[u8; 32]) -> CkbH256 {
        let message_magic = b"\x19Dogecoin Signed Message:\n\x40";
        let msg_hex = hex::encode(message);
        assert_eq!(msg_hex.len(), 64);

        let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
        temp2.put(Bytes::from(message_magic.to_vec()));
        temp2.put(Bytes::from(hex::encode(message)));

        let msg = calculate_sha256(&temp2.to_vec());
        let msg = calculate_sha256(&msg);

        CkbH256::from(msg)
    }

    pub fn sign(&self, privkey: &Privkey, message: CkbH256) -> Bytes {
        self.0.sign(privkey, message)
    }
}

#[derive(Default)]
pub struct EOSConfig(pub BitcoinConfig);

impl EOSConfig {
    pub fn get_pubkey_hash(&self, pubkey: &Pubkey) -> [u8; 20] {
        if self.0.pubkey_err {
            let mut r = [0u8; 20];
            thread_rng().fill_bytes(&mut r);
            return r;
        }
        // EOS support
        let buf = match self.0.sign_vtype {
            BITCOIN_V_TYPE_P2PKHUNCOMPRESSED => {
                let mut temp: BytesMut = BytesMut::with_capacity(65);
                temp.put_u8(4);
                temp.put(Bytes::from(pubkey.as_bytes().to_vec()));
                temp.freeze().to_vec()
            }
            BITCOIN_V_TYPE_P2PKHCOMPRESSED => pubkey.serialize(),
            _ => {
                panic!("unsupport")
            }
        };

        ckb_hash::blake2b_256(buf)[..20].try_into().unwrap()
    }

    pub fn convert_message(&self, message: &[u8; 32]) -> CkbH256 {
        CkbH256::from_slice(message).unwrap()
    }

    pub fn sign(&self, privkey: &Privkey, message: CkbH256) -> Bytes {
        self.0.sign(privkey, message)
    }
}

#[derive(Default)]
pub struct TronConfig {
    pub pubkey_err: bool,
}

impl TronConfig {
    pub fn get_pubkey_hash(&self, pubkey: &Pubkey) -> [u8; 20] {
        if self.pubkey_err {
            let mut r = [0u8; 20];
            thread_rng().fill_bytes(&mut r);
            return r;
        }

        let pubkey = pubkey.as_bytes();

        let mut hasher = Keccak256::new();
        hasher.update(&pubkey.to_vec());
        let r = hasher.finalize().as_slice().to_vec();

        r[12..].try_into().unwrap()
    }

    pub fn convert_message(&self, message: &[u8; 32]) -> CkbH256 {
        let eth_prefix: &[u8; 24] = b"\x19TRON Signed Message:\n32";
        let mut hasher = Keccak256::new();
        hasher.update(eth_prefix);
        hasher.update(message);
        let r = hasher.finalize();
        let rr = CkbH256::from_slice(r.as_slice()).expect("convert_keccak256_hash");
        rr
    }
}

pub struct TestConfig {
    pub id: Identity,
    pub acp_config: Option<(u8, u8)>,
    pub use_rc: bool,
    pub use_rc_identity: bool,
    pub scheme: TestScheme,
    pub scheme2: TestScheme2,
    pub rc_root: Bytes,
    pub proofs: Vec<Vec<u8>>,
    pub proof_masks: Vec<u8>,
    pub private_key: Privkey,
    pub pubkey: Pubkey,

    pub multisig: MultisigTestConfig,
    pub smt_in_input: bool,

    pub rsa_private_key: PKey<Private>,
    pub rsa_pubkey: PKey<Public>,
    pub rsa_script: Script,
    // when this is on, sign by RSA
    pub use_rsa: bool,

    // when this is on, sign by ISO9796-2
    pub use_iso9796_2: bool,

    pub preimage_len: usize,
    pub sig_len: usize,

    // since
    pub use_since: bool,
    pub args_since: u64,
    pub input_since: u64,

    // sudt supply
    pub use_supply: bool,
    pub info_cell: [u8; 32],

    pub running_script: Script,
    pub leading_witness_count: usize,

    // Bitcoin
    pub eos: Option<EOSConfig>,
    pub tron: Option<TronConfig>,
    pub bitcoin: Option<BitcoinConfig>,
    pub dogecoin: Option<DogecoinConfig>,
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

    OwnerLockMismatched,
    OwnerLockWithoutWitness,

    RsaWrongSignature,
}

#[derive(Copy, Clone, PartialEq)]
pub enum TestScheme2 {
    None,
    NoWitness,
}

const RC_ROOT_MASK: u8 = 1;
const ACP_MASK: u8 = 2;
const SINCE_MASK: u8 = 4;
const SUPPLY_MASK: u8 = 8;

impl TestConfig {
    pub fn new(flags: u8, use_rc: bool) -> TestConfig {
        let private_key: Privkey = Generator::random_privkey();
        let pubkey = private_key.pubkey().expect("pubkey");
        let pubkey_hash = blake160(&pubkey.serialize());

        let blake160 = if flags == IDENTITY_FLAGS_PUBKEY_HASH {
            pubkey_hash
        } else if flags == IDENTITY_FLAGS_ETHEREUM {
            keccak160(&pubkey.as_ref()[..])
        } else {
            Bytes::from(&[0; 20][..])
        };

        let rc_root: Bytes = {
            let mut buf = BytesMut::new();
            buf.resize(32, 0);
            buf.freeze()
        };
        // rsa key
        let bits = 1024;
        let rsa = Rsa::generate(bits).unwrap();
        let rsa_private_key = PKey::from_rsa(rsa).unwrap();

        let public_key_pem: Vec<u8> = rsa_private_key.public_key_to_pem().unwrap();
        let rsa_pubkey = PKey::public_key_from_pem(&public_key_pem).unwrap();

        let preimage_len = if flags == IDENTITY_FLAGS_DL {
            53
        } else if flags == IDENTITY_FLAGS_EXEC {
            62
        } else {
            0
        };
        let sig_len = 65;

        TestConfig {
            id: Identity { flags, blake160 },
            acp_config: None,
            use_rc,
            use_rc_identity: true,
            rc_root,
            scheme: TestScheme::None,
            scheme2: TestScheme2::None,
            proofs: Default::default(),
            proof_masks: Default::default(),
            private_key,
            pubkey,
            multisig: Default::default(),
            smt_in_input: false,
            rsa_private_key,
            rsa_pubkey,
            rsa_script: Default::default(),
            sig_len,
            preimage_len,
            use_rsa: false,
            use_since: false,
            args_since: 0,
            input_since: 0,
            use_iso9796_2: false,
            use_supply: false,
            info_cell: Default::default(),
            running_script: Default::default(),
            leading_witness_count: 0,

            eos: None,
            tron: None,
            bitcoin: None,
            dogecoin: None,
        }
    }

    pub fn set_scheme(&mut self, scheme: TestScheme) {
        self.scheme = scheme;
    }
    pub fn set_rsa(&mut self) {
        self.use_rsa = true;
        self.sig_len = 264;
    }
    pub fn set_iso9796_2(&mut self) {
        self.use_iso9796_2 = true;
        self.sig_len = 648;
    }
    pub fn set_multisig(&mut self, require_first_n: u8, threshold: u8, count: u8) {
        self.multisig = Default::default();
        self.multisig.set(require_first_n, threshold, count);
        self.id = self.multisig.gen_identity();

        self.sig_len = 4 + 20 * count as usize + 65 * threshold as usize;
    }

    pub fn set_acp_config(&mut self, min_config: Option<(u8, u8)>) {
        self.acp_config = min_config;
    }

    pub fn set_since(&mut self, args_since: u64, input_since: u64) {
        self.args_since = args_since;
        self.input_since = input_since;
        self.use_since = true;
    }

    pub fn set_sudt_supply(&mut self, cell_id: [u8; 32]) {
        self.info_cell = cell_id;
        self.use_supply = true;
    }

    pub fn set_omni_identity(&mut self, used: bool) {
        self.use_rc_identity = used;
    }

    pub fn set_eos(&mut self, eos: EOSConfig) {
        let pkhash = eos.get_pubkey_hash(&self.pubkey);
        self.eos = Some(eos);
        self.id.blake160 = Bytes::from(pkhash.to_vec());
    }

    pub fn set_tron(&mut self, tron: TronConfig) {
        let pkhash = tron.get_pubkey_hash(&self.pubkey);
        self.tron = Some(tron);
        self.id.blake160 = Bytes::from(pkhash.to_vec());
    }

    pub fn set_bitcoin(&mut self, btc: BitcoinConfig) {
        let pkhash = btc.get_pubkey_hash(&self.pubkey);
        self.bitcoin = Some(btc);
        self.id.blake160 = Bytes::from(pkhash.to_vec());
    }

    pub fn set_dogecoin(&mut self, dogecoin: DogecoinConfig) {
        let pkhash = dogecoin.get_pubkey_hash(&self.pubkey);
        self.dogecoin = Some(dogecoin);
        self.id.blake160 = Bytes::from(pkhash.to_vec());
    }

    pub fn gen_args(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(128);
        let mut omni_lock_flags: u8 = 0;

        if self.use_rc {
            if self.use_rc_identity {
                omni_lock_flags |= RC_ROOT_MASK;

                bytes.resize(21, 0);
                bytes.put(&[omni_lock_flags][..]);
                bytes.put(self.rc_root.as_ref());
            } else {
                omni_lock_flags |= RC_ROOT_MASK;
                // auth
                bytes.put_u8(self.id.flags);
                bytes.put(self.id.blake160.as_ref());
                // rc_root
                bytes.put(&[omni_lock_flags][..]);
                bytes.put(self.rc_root.as_ref());
            }
        } else {
            bytes.put_u8(self.id.flags);
            bytes.put(self.id.blake160.as_ref());

            let mut omni_lock_args = Vec::<u8>::new();

            // acp
            if self.acp_config.is_some() {
                omni_lock_flags |= ACP_MASK;
            }
            // since
            if self.use_since {
                omni_lock_flags |= SINCE_MASK;
            }
            // sudt supply
            if self.use_supply {
                omni_lock_flags |= SUPPLY_MASK;
            }
            omni_lock_args.push(omni_lock_flags);

            if let Some((ckb_min, udt_min)) = self.acp_config {
                omni_lock_args.push(ckb_min);
                omni_lock_args.push(udt_min);
            }
            if self.use_since {
                omni_lock_args.extend(self.args_since.to_le_bytes().iter());
            }
            if self.use_supply {
                omni_lock_args.extend(self.info_cell.iter());
            }
            bytes.put(omni_lock_args.as_slice());
        }
        bytes.freeze()
    }

    pub fn is_owner_lock(&self) -> bool {
        self.id.flags == IDENTITY_FLAGS_OWNER_LOCK
    }
    pub fn is_pubkey_hash(&self) -> bool {
        self.id.flags == IDENTITY_FLAGS_PUBKEY_HASH
    }
    pub fn is_rc(&self) -> bool {
        self.use_rc
    }
    pub fn is_acp(&self) -> bool {
        self.acp_config.is_some()
    }
}

pub fn gen_witness_lock(
    sig: Bytes,
    use_rc: bool,
    use_rc_identity: bool,
    proofs: &SmtProofEntryVec,
    identity: &omni_lock::Auth,
    preimage: Option<Bytes>,
) -> Bytes {
    let builder = OmniLockWitnessLock::new_builder();

    let mut builder = builder.signature(Some(sig).pack());

    if let Some(p) = preimage {
        builder = builder.preimage(Some(p).pack());
    }

    if use_rc && use_rc_identity {
        let rc_identity = omni_lock::IdentityBuilder::default()
            .identity(identity.clone())
            .proofs(proofs.clone())
            .build();
        let opt = omni_lock::IdentityOpt::new_unchecked(rc_identity.as_bytes());
        builder = builder.omni_identity(opt);
    }
    builder.build().as_bytes()
}

/* generate the following structure:
typedef struct RsaInfo {
  uint8_t algorithm_id;
  uint8_t key_size;
  uint8_t padding;
  uint8_t md_type;
  uint32_t E;
  uint8_t N[PLACEHOLDER_SIZE];
  uint8_t sig[PLACEHOLDER_SIZE];
} RsaInfo;
*/
pub fn rsa_sign(msg: &[u8], key: &PKey<Private>) -> (Vec<u8>, Vec<u8>) {
    let pem: Vec<u8> = key.public_key_to_pem().unwrap();
    let pubkey = PKey::public_key_from_pem(&pem).unwrap();

    let mut sig = Vec::<u8>::new();
    sig.push(1); // algorithm id
    sig.push(1); // key size, 1024
    sig.push(0); // padding, PKCS# 1.5
    sig.push(6); // hash type SHA256

    let pubkey2 = pubkey.rsa().unwrap();
    let mut e = pubkey2.e().to_vec();
    let mut n = pubkey2.n().to_vec();
    e.reverse();
    n.reverse();

    while e.len() < 4 {
        e.push(0);
    }
    while n.len() < 128 {
        n.push(0);
    }
    sig.append(&mut e); // 4 bytes E
    sig.append(&mut n); // N

    let my_pubkey = sig.clone();

    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(&msg).unwrap();
    sig.extend(signer.sign_to_vec().unwrap()); // sig

    (sig, my_pubkey)
}

/*
generate the following structure:
typedef struct RsaInfo {
    uint8_t algorithm_id;
    uint8_t key_size;
    uint8_t padding;
    uint8_t md_type;
    uint32_t E;
    uint8_t N[PLACEHOLDER_SIZE];
    uint8_t sig[PLACEHOLDER_SIZE];

    // note, there are totally 4 signatures
    uint8_t sig[PLACEHOLDER_SIZE];
    uint8_t sig[PLACEHOLDER_SIZE];
    uint8_t sig[PLACEHOLDER_SIZE];
} RsaInfo;
*/

pub fn iso9796_2_batch_sign(msg: &[u8], key: &PKey<Private>) -> (Vec<u8>, Vec<u8>) {
    let pem: Vec<u8> = key.public_key_to_pem().unwrap();
    let pubkey = PKey::public_key_from_pem(&pem).unwrap();

    let mut sig = Vec::<u8>::new();
    sig.push(3); // algorithm id, CKB_VERIFY_ISO9796_2_BATCH
    sig.push(1); // key size, 1024
    sig.push(0); // padding, PKCS# 1.5
    sig.push(6); // hash type SHA256

    let pubkey2 = pubkey.rsa().unwrap();
    let mut e = pubkey2.e().to_vec();
    let mut n = pubkey2.n().to_vec();
    e.reverse();
    n.reverse();

    while e.len() < 4 {
        e.push(0);
    }
    while n.len() < 128 {
        n.push(0);
    }
    sig.append(&mut e); // 4 bytes E
    sig.append(&mut n); // N

    let my_pubkey = sig.clone();

    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(&msg).unwrap();
    sig.extend(signer.sign_to_vec().unwrap()); // sig
    sig.extend(signer.sign_to_vec().unwrap()); // sig
    sig.extend(signer.sign_to_vec().unwrap()); // sig
    sig.extend(signer.sign_to_vec().unwrap()); // sig

    (sig, my_pubkey)
}

pub fn gen_zero_witness_lock(
    use_rc: bool,
    use_rc_identity: bool,
    proofs: &SmtProofEntryVec,
    identity: &omni_lock::Auth,
    sig_len: usize,
    preimage_len: usize,
) -> Bytes {
    let mut zero = BytesMut::new();
    zero.resize(sig_len, 0);

    let preimage = if preimage_len > 0 {
        let mut zero2 = BytesMut::new();
        zero2.resize(preimage_len, 0);
        Some(zero2.freeze())
    } else {
        None
    };
    let witness_lock = gen_witness_lock(
        zero.freeze(),
        use_rc,
        use_rc_identity,
        proofs,
        identity,
        preimage,
    );

    let mut res = BytesMut::new();
    res.resize(witness_lock.len(), 0);
    res.freeze()
}

pub fn gen_exec_preimage(script: &Script, blake160: &Bytes) -> Bytes {
    let mut result = BytesMut::new();
    result.put_slice(script.code_hash().as_slice());
    result.put_slice(script.hash_type().as_slice());
    result.put_slice(blake160.clone().as_ref());

    result.freeze()
}
// first generate N RCE cells with each contained one RCRule
// then collect all these RCE cell hash and create the final RCE cell.
pub fn generate_rce_cell(
    dummy: &mut DummyDataLoader,
    mut tx_builder: TransactionBuilder,
    rc_data: Vec<Bytes>,
    smt_in_input: bool,
) -> (Byte32, TransactionBuilder) {
    let mut rng = thread_rng();
    let mut cell_vec_builder = RCCellVecBuilder::default();

    for rc_rule in rc_data {
        let mut random_args: [u8; 32] = Default::default();
        rng.fill(&mut random_args[..]);
        // let's first build the RCE cell which contains the RCData(RCRule/RCCellVec).
        let (b0, rce_script) = build_script(
            dummy,
            tx_builder,
            true,
            smt_in_input,
            &rc_rule,
            Bytes::copy_from_slice(random_args.as_ref()),
        );
        tx_builder = b0;
        // rce_script is in "old" blockchain types
        let hash = rce_script.code_hash();

        cell_vec_builder =
            cell_vec_builder.push(Byte32::from_slice(hash.as_slice()).expect("Byte32::from_slice"));
    }

    let cell_vec = cell_vec_builder.build();

    let rce_cell_content = RCDataBuilder::default()
        .set(RCDataUnion::RCCellVec(cell_vec))
        .build();

    let mut random_args: [u8; 32] = Default::default();
    rng.fill(&mut random_args[..]);

    let bin = rce_cell_content.as_slice();

    // let's first build the RCE cell which contains the RCData(RCRule/RCCellVec).
    let (b0, rce_script) = build_script(
        dummy,
        tx_builder,
        true,
        smt_in_input,
        &Bytes::copy_from_slice(bin),
        Bytes::copy_from_slice(random_args.as_ref()),
    );
    tx_builder = b0;

    (rce_script.code_hash(), tx_builder)
}

pub fn generate_proofs(
    scheme: TestScheme,
    smt_key: &Vec<[u8; 32]>,
) -> (Vec<Vec<u8>>, Vec<Bytes>, Vec<u8>) {
    let mut proofs = Vec::<Vec<u8>>::default();
    let mut rc_data = Vec::<Bytes>::default();
    let mut proof_masks = Vec::<u8>::default();

    match scheme {
        TestScheme::BothOn => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnBlackList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(3);
            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(3);
        }
        TestScheme::OnlyInputOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::NotOnWhiteList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        TestScheme::OnlyOutputOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::NotOnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        TestScheme::BothOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        _ => {
            let (proof1, rc_data1) = generate_single_proof(scheme, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(3);
        }
    }

    (proofs, rc_data, proof_masks)
}

pub fn generate_single_proof(scheme: TestScheme, smt_key: &Vec<[u8; 32]>) -> (Vec<u8>, Bytes) {
    let hash = smt_key.clone();
    let mut is_black_list = false;
    let mut is_emergency_halt = false;
    let (smt_root, proof) = match scheme {
        TestScheme::OnWhiteList => {
            is_black_list = false;
            build_smt_on_wl(&hash, true)
        }
        TestScheme::NotOnWhiteList => {
            is_black_list = false;
            build_smt_on_wl(&hash, false)
        }
        TestScheme::OnBlackList => {
            is_black_list = true;
            build_smt_on_bl(&hash, true)
        }
        TestScheme::NotOnBlackList => {
            is_black_list = true;
            build_smt_on_bl(&hash, false)
        }
        TestScheme::EmergencyHaltMode => {
            is_emergency_halt = true;
            (H256::default(), Vec::<u8>::default())
        }
        _ => (H256::default(), Vec::<u8>::default()),
    };

    let rc_data = build_rc_rule(&smt_root.into(), is_black_list, is_emergency_halt);
    (proof, rc_data)
}

pub fn assert_script_error(err: Error, err_code: i8) {
    // For ckb 0.40.0
    // use ckb_error::assert_error_eq;
    // use ckb_script::ScriptError;
    // assert_error_eq!(
    //     err,
    //     ScriptError::ValidationFailure(err_code).input_lock_script(1)
    // );

    let error_string = err.to_string();
    assert!(
        error_string.contains(format!("error code {}", err_code).as_str()),
        "error_string: {}, expected_error_code: {}",
        error_string,
        err_code
    );
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

pub fn calculate_sha256(buf: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut c = Sha256::new();
    c.update(buf);
    c.finalize().into()
}

pub fn calculate_ripemd160(buf: &[u8]) -> [u8; 20] {
    use ripemd::{Digest, Ripemd160};

    let mut hasher = Ripemd160::new();
    hasher.update(buf);
    let buf = hasher.finalize()[..].to_vec();

    buf.try_into().unwrap()
}

pub fn bitcoin_hash160(buf: &[u8]) -> [u8; 20] {
    calculate_ripemd160(&calculate_sha256(buf))
}
