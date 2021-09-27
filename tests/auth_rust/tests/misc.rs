use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
use ckb_crypto::secp::Privkey;
use ckb_error::Error;
use ckb_script::TxVerifyEnv;
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        hardfork::HardForkSwitch,
        Capacity, DepType, EpochNumberWithFraction, HeaderView, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    packed::{
        self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs,
        WitnessArgsBuilder,
    },
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use log::{Metadata, Record};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, mem::size_of, vec};

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;

lazy_static! {
    pub static ref AUTH_DEMO: Bytes = Bytes::from(&include_bytes!("../../../build/auth_demo")[..]);
    pub static ref AUTH_DL: Bytes = Bytes::from(&include_bytes!("../../../build/auth")[..]);
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../build/secp256k1_data")[..]);
    pub static ref ALWAYS_SUCCESS: Bytes =
        Bytes::from(&include_bytes!("../../../build/always_success")[..]);
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

pub fn sign_tx(tx: TransactionView, key: &Privkey, config: &TestConfig) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group(tx, key, config, 0, witnesses_len)
}

pub fn sign_tx_by_input_group(
    tx: TransactionView,
    key: &Privkey,
    config: &TestConfig,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let mut rng = thread_rng();
    let tx_hash = tx.hash();
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
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(SIGNATURE_SIZE, 0);
                    buf.into()
                };
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
                if config.incorrect_msg {
                    rng.fill(&mut message);
                }
                let message = H256::from(message);
                let sig = key.sign_recoverable(&message).expect("sign").serialize();
                witness
                    .as_builder()
                    .lock(Some(Bytes::from(sig)).pack())
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

fn append_cell_deps(
    dummy: &mut DummyDataLoader,
    deps_data: &Bytes,
    const_hash: &[u8; 32],
) -> OutPoint {
    // setup sighash_all dep
    let sighash_all_out_point = {
        let rand_hash = {
            const_hash.pack()
        };
        OutPoint::new(rand_hash, 0)
    };

    // dep contract code
    let sighash_all_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(deps_data.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (sighash_all_cell, deps_data.clone()),
    );

    sighash_all_out_point
}

fn append_cells_deps<R: Rng>(
    dummy: &mut DummyDataLoader,
    rng: &mut R,
    config: &TestConfig,
) -> (Capacity, TransactionBuilder) {
    
    let mut auth_demo_rand_hash: [u8; 32] = [0; 32];
    let mut auth_dl_rand_hash: [u8; 32] = [0; 32];
    let mut secp256_rand_hash: [u8; 32] = [0; 32];
    if config.use_const_val {
        auth_demo_rand_hash = [
            0x97, 0xbc, 0x16, 0x9f, 0x11, 0x04, 0xdb, 0x02, 
            0xf1, 0xf4, 0xc4, 0xfe, 0xa6, 0xd2, 0xf2, 0xd0, 
            0x9b, 0x82, 0xfd, 0x21, 0x32, 0xe7, 0x03, 0xc8, 
            0xe8, 0x00, 0x90, 0xbf, 0xb5, 0x8c, 0x06, 0x4e, 
        ];
        auth_dl_rand_hash = [
            0x02, 0x0a, 0x2a, 0x68, 0x2a, 0x7e, 0x10, 0x4e, 
            0x42, 0x91, 0x42, 0x80, 0x05, 0x3c, 0xca, 0x5f, 
            0x57, 0x23, 0xc2, 0xd1, 0x86, 0xfb, 0x26, 0xf4, 
            0xa0, 0x9b, 0xc4, 0x5b, 0x90, 0x65, 0x8e, 0xf0, 
        ];
        secp256_rand_hash = [
            0x94, 0x00, 0xba, 0x86, 0xc6, 0x06, 0x34, 0xeb, 
            0xa9, 0x71, 0x55, 0x16, 0x01, 0x44, 0x1d, 0x86, 
            0x74, 0x0c, 0x10, 0x42, 0xce, 0xbc, 0x8d, 0x1f, 
            0xaf, 0x69, 0xdd, 0x90, 0xe7, 0x75, 0xa6, 0xe7, 
        ];
    } else {
        rng.fill(&mut auth_demo_rand_hash);
        rng.fill(&mut auth_dl_rand_hash);
        rng.fill(&mut secp256_rand_hash);
    }

    let sighash_all_out_point = append_cell_deps(dummy,&AUTH_DEMO,&auth_demo_rand_hash);
    let sighash_dl_out_point = append_cell_deps(dummy, &AUTH_DL, &auth_dl_rand_hash);
    let secp256k1_data_out_point = append_cell_deps(dummy, &SECP256K1_DATA_BIN, &secp256_rand_hash);

    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_all_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_dl_out_point)
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
    (dummy_capacity, tx_builder)
}

pub fn gen_tx(
    dummy: &mut DummyDataLoader,
    lock_args: Bytes,
    config: &TestConfig,
) -> TransactionView {
    let mut rng = thread_rng();
    gen_tx_with_grouped_args(
        dummy,
        vec![(lock_args, config.sign_size as usize)],
        &mut rng,
        config,
    )
}

pub fn gen_tx_with_grouped_args<R: Rng>(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    rng: &mut R,
    config: &TestConfig,
) -> TransactionView {
    let (dummy_capacity, mut tx_builder) = append_cells_deps(dummy, rng, config);
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&AUTH_DEMO);

    for (args, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let previous_tx_hash;
            if config.use_const_val {
                previous_tx_hash = {
                    let buf = [
                        0x7d, 0x79, 0x35, 0x8e, 0x35, 0x6e, 0x5f, 0xfc,
                        0x3d, 0x0f, 0xcf, 0x40, 0xe3, 0x9b, 0x27, 0x74,
                        0xf9, 0xbb, 0x5f, 0x0f, 0x48, 0xeb, 0xd2, 0xe1,
                        0xd7, 0x6f, 0x48, 0xe1, 0x3e, 0x46, 0xce, 0x11,
                    ];
                    buf.pack()
                };
            } else {
                previous_tx_hash = {
                    let mut buf = [0u8; 32];
                    rng.fill(&mut buf);
                    buf.pack()
                };
            }
            let previous_out_point = OutPoint::new(previous_tx_hash, 0);
            let script = Script::new_builder()
                .args(args.pack())
                .code_hash(sighash_all_cell_data_hash.clone())
                .hash_type(ScriptHashType::Data1.into())
                .build();
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script)
                .build();
            dummy.cells.insert(
                previous_out_point.clone(),
                (previous_output_cell.clone(), Bytes::new()),
            );
            let mut buf = BytesMut::with_capacity(65);

            if config.use_const_val {
                buf.put(Bytes::from(config.rand_buf.to_vec()));
            }else{
                let mut random_extra_witness = [0u8; 64];
                rng.fill(&mut random_extra_witness);
                buf.put(Bytes::from(random_extra_witness.to_vec()));
            }

            let witness_args = WitnessArgsBuilder::default()
                .input_type(Some(Bytes::from(buf.to_vec())).pack())
                .build();
            tx_builder = tx_builder
                .input(CellInput::new(previous_out_point, 0))
                .witness(witness_args.as_bytes().pack());
        }
    }

    tx_builder.build()
}

#[derive(Serialize, Deserialize)]
struct CkbAuthType {
    algorithm_id: u8,
    content: [u8; 20],
}

#[derive(Serialize, Deserialize)]
struct EntryType {
    code_hash: [u8; 32],
    hash_type: u8,
    entry_category: u8,
}

#[derive(Clone)]
pub enum EntryCategoryType {
    Exec = 0,
    DynamicLinking = 1,
}

#[derive(Clone)]
pub enum AlgorithmType {
    Ckb = 0,
    Ethereum = 1,
    Eos = 2,
    Tron = 3,
    Bitcoin = 4,
    Dogecoin = 5,
    CkbMultisig = 6,
    SchnorrOrTaproot = 7,
    Iso9796_2 = 8,
    RSA = 9,
    OwnerLock = 0xFC,
}

pub struct TestConfig {
    pub algorithm_type: AlgorithmType,
    pub entry_category_type: EntryCategoryType,
    pub privkey: Privkey,

    pub sign_size: i32,

    pub incorrect_pubkey: bool,
    pub incorrect_msg: bool,

    pub use_const_val: bool,
    pub rand_buf: [u8; 64],
}

impl TestConfig {
    pub fn new(
        algorithm_type: AlgorithmType,
        entry_category_type: EntryCategoryType,
        privkey: Privkey,
        sign_size: i32,
    ) -> TestConfig {
        assert!(sign_size > 0);
        TestConfig {
            algorithm_type,
            entry_category_type,
            privkey,
            sign_size,
            incorrect_pubkey: false,
            incorrect_msg: false,
            use_const_val: false,
            rand_buf: [0; 64],
        }
    }
}

pub fn gen_args(config: &TestConfig) -> Bytes {
    let mut ckb_auth_type = CkbAuthType {
        algorithm_id: config.algorithm_type.clone() as u8,
        content: [0; 20],
    };

    let mut entry_type = EntryType {
        code_hash: [0; 32],
        hash_type: ScriptHashType::Data1.into(),
        entry_category: config.entry_category_type.clone() as u8,
    };

    if !config.incorrect_pubkey {
        let mut blake2b = ckb_hash::new_blake2b();
        let pubkey = config.privkey.pubkey().expect("pubkey");
        blake2b.update(pubkey.serialize().as_slice());
        let mut pub_hash: [u8; 32] = [0; 32];
        blake2b.finalize(&mut pub_hash);
        ckb_auth_type.content.copy_from_slice(&pub_hash[0..20]);
    } else {
        let mut rng = thread_rng();
        let incorrect_pubkey = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            Vec::from(buf)
        };
        ckb_auth_type
            .content
            .copy_from_slice(&incorrect_pubkey.as_slice()[0..20]);
    }

    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&AUTH_DL);
    entry_type
        .code_hash
        .copy_from_slice(sighash_all_cell_data_hash.as_slice());

    let mut bytes = BytesMut::with_capacity(size_of::<CkbAuthType>() + size_of::<EntryType>());
    bytes.put(Bytes::from(bincode::serialize(&ckb_auth_type).unwrap()));
    bytes.put(Bytes::from(bincode::serialize(&entry_type).unwrap()));

    bytes.freeze()
}

pub fn build_resolved_tx(
    data_loader: &DummyDataLoader,
    tx: &TransactionView,
) -> ResolvedTransaction {
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|deps_out_point| {
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point())
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

pub fn debug_printer(script: &Byte32, msg: &str) {
    let slice = script.as_slice();
    let _str = format!(
        "Script({:x}{:x}{:x}{:x}{:x})",
        slice[0], slice[1], slice[2], slice[3], slice[4]
    );
    //println!("{:?}: {}", _str, msg);
    print!("{}", msg);
}

pub struct MyLogger;

impl log::Log for MyLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        println!("{}:{} - {}", record.level(), record.target(), record.args());
    }
    fn flush(&self) {}
}

pub enum AuthErrorCodeType {
    NotImplemented = 100,
    Mismatched,
    InvalidArg,
    ErrorWrongState,
    // exec
    ExecInvalidLength,
    ExecInvalidParam,
    ExecNotPaired,
    ExecInvalidSig,
    ExecInvalidMsg,
}

pub fn assert_script_error(err: Error, err_code: AuthErrorCodeType) {
    let err_code = err_code as i8;
    let error_string = err.to_string();
    assert!(
        error_string.contains(format!("error code {}", err_code).as_str()),
        "error_string: {}, expected_error_code: {}",
        error_string,
        err_code
    );
}
