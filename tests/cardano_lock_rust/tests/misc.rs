use cardano_lock_rust::{blockchain, cardano_lock_mol};
use cardano_message_signing::{
    builders::{AlgorithmId, COSESign1Builder},
    cbor::CBORValue,
    utils::ToBytes,
    HeaderMap, Headers, Label, ProtectedHeaderMap,
};
use cardano_serialization_lib::crypto::PrivateKey;
use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
use ckb_script::TxVerifyEnv;
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
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
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng, RngCore};
use std::collections::HashMap;

lazy_static! {
    pub static ref CARDANO_LOCK_BIN: ckb_types::bytes::Bytes =
        ckb_types::bytes::Bytes::from(include_bytes!("../../../build/cardano_lock").as_ref());
    pub static ref ALWAYS_SUCCESS_BIN: ckb_types::bytes::Bytes =
        ckb_types::bytes::Bytes::from(include_bytes!("../../../build/always_success").as_ref());
}

pub const MAX_CYCLES: u64 = std::u64::MAX;

fn _print_mem(d: &[u8]) {
    let mut c = 0;
    for i in 0..d.len() {
        c = i;
        print!("{:#04X}, ", d[i]);
        if i % 16 == 15 {
            print!("\n");
        }
    }
    if c % 16 != 15 {
        print!("\n");
    }
}

pub fn _dbg_print_mem(d: &[u8], n: &str) {
    println!("{}, size:{}", n, d.len());
    _print_mem(d);
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
    let hash = Vec::from(&ckb_hash::blake2b_256(message)[..]);
    Bytes::from(hash)
}

fn to_array<T, const N: usize>(d: Vec<T>) -> [T; N] {
    d.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}
fn to_byte32(d: &Byte32) -> blockchain::Byte32 {
    let d = d
        .as_slice()
        .to_vec()
        .into_iter()
        .map(|f| molecule::prelude::Byte::new(f))
        .collect();
    blockchain::Byte32Builder::default()
        .set(to_array(d))
        .build()
}
fn to_byte64(d: &Vec<u8>) -> cardano_lock_mol::Byte64 {
    let d = d
        .as_slice()
        .to_vec()
        .into_iter()
        .map(|f| molecule::prelude::Byte::new(f))
        .collect();
    cardano_lock_mol::Byte64Builder::default()
        .set(to_array(d))
        .build()
}
fn to_bytes(d: &Vec<u8>) -> blockchain::Bytes {
    let d: Vec<molecule::prelude::Byte> = d
        .to_vec()
        .into_iter()
        .map(|f| molecule::prelude::Byte::new(f))
        .collect();
    let r = blockchain::BytesBuilder::default();
    let r = r.set(d);
    r.build()
}

pub struct Config {
    pub random: ThreadRng,
    pub random_sign_data: bool,
    pub random_sign_pubkey: bool,
    pub random_message: bool,

    pub privkey: PrivateKey,
    pub stake_privkey: PrivateKey,
}

impl Config {
    pub fn new() -> Self {
        let mut rad = thread_rng();
        let sk_bytes1: [u8; 32] = {
            let mut data: [u8; 32] = [0; 32];
            rad.fill_bytes(&mut data);
            data
        };
        let sk_bytes2: [u8; 32] = {
            let mut data: [u8; 32] = [0; 32];
            rad.fill_bytes(&mut data);
            data
        };
        Self {
            random: rad,
            random_sign_data: false,
            random_sign_pubkey: false,
            random_message: false,
            privkey: PrivateKey::from_normal_bytes(&sk_bytes1).unwrap(),
            stake_privkey: PrivateKey::from_normal_bytes(&sk_bytes2).unwrap(),
        }
    }

    pub fn rnd_array_32(&mut self) -> [u8; 32] {
        let mut data: [u8; 32] = [0; 32];
        self.random.fill_bytes(&mut data);
        data
    }
}

fn gen_witness_data(config: &mut Config, payload: &Byte32) -> Bytes {
    let mut witness_builder = cardano_lock_mol::CardanoWitnessLockBuilder::default();
    let mut pubkey = config.privkey.to_public().as_bytes();
    if config.random_sign_pubkey == true {
        config.random.fill_bytes(&mut pubkey.as_mut());
    };
    witness_builder = witness_builder.pubkey(to_byte32(&Byte32::new(to_array(pubkey))));

    let mut protected_headers = HeaderMap::new();
    protected_headers.set_algorithm_id(&Label::from_algorithm_id(AlgorithmId::EdDSA.into()));

    let base_addr = cardano_serialization_lib::address::BaseAddress::new(
        0,
        &cardano_serialization_lib::address::StakeCredential::from_keyhash(
            &config.privkey.to_public().hash(),
        ),
        &cardano_serialization_lib::address::StakeCredential::from_keyhash(
            &config.stake_privkey.to_public().hash(),
        ),
    );
    protected_headers
        .set_header(
            &Label::new_text(String::from("address")),
            &CBORValue::new_bytes(base_addr.to_address().to_bytes()),
        )
        .expect("set header failed");

    let protected_serialized = ProtectedHeaderMap::new(&protected_headers);

    //let protected_serialized = ProtectedHeaderMap::new(&HeaderMap::new());

    let headers = Headers::new(&protected_serialized, &HeaderMap::new());
    let builder = COSESign1Builder::new(&headers, payload.as_slice().to_vec(), false);
    let to_sign = builder.make_data_to_sign();
    witness_builder = witness_builder.new_message(to_bytes(&to_sign.to_bytes()));

    let mut sig = config.privkey.sign(&to_sign.to_bytes()).to_bytes();
    if config.random_sign_data == true {
        for _i in 0..4 {
            let source_sig = sig.clone();
            config.random.fill_bytes(&mut sig.as_mut());
            if source_sig != sig {
                break;
            }
        }
    }
    witness_builder = witness_builder.signature(to_byte64(&sig));

    let witness_data = witness_builder.build();
    witness_data.as_bytes()
}

pub fn sign_tx(tx: TransactionView, config: &mut Config) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group(tx, 0, witnesses_len, config)
}

pub fn sign_tx_by_input_group(
    tx: TransactionView,
    begin_index: usize,
    len: usize,
    config: &mut Config,
) -> TransactionView {
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
                    buf.resize(witness.as_bytes().len() - 20, 0);
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

                if config.random_message == true {
                    message = config.rnd_array_32();
                }
                let message = H256::from(message);

                let witness_data =
                    gen_witness_data(config, &Byte32::new(to_array(message.as_bytes().to_vec())));
                witness
                    .as_builder()
                    .lock(Some(witness_data).pack())
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

pub fn gen_tx(
    dummy: &mut DummyDataLoader,
    lock_args: Bytes,
    config: &mut Config,
) -> TransactionView {
    gen_tx_with_grouped_args(dummy, vec![(lock_args, 1)], config)
}

pub fn gen_tx_with_grouped_args(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    config: &mut Config,
) -> TransactionView {
    let cardano_cell_data_hash = CellOutput::calc_data_hash(&CARDANO_LOCK_BIN);
    // setup cardano dep
    let cardano_data_out_point = {
        let tx_hash = {
            let mut buf = [0u8; 32];
            config.random.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(tx_hash, 0)
    };
    let cardano_data_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(CARDANO_LOCK_BIN.len())
                .expect("data capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        cardano_data_out_point.clone(),
        (cardano_data_cell, CARDANO_LOCK_BIN.clone()),
    );
    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(cardano_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    for (args, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let previous_tx_hash = {
                let mut buf = [1u8; 32];
                config.random.fill(&mut buf);
                buf.pack()
            };
            let previous_out_point = OutPoint::new(previous_tx_hash, 0);
            let script = Script::new_builder()
                .args(args.pack())
                .code_hash(cardano_cell_data_hash.clone())
                .hash_type(ScriptHashType::Data.into())
                .build();
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script)
                .build();
            dummy.cells.insert(
                previous_out_point.clone(),
                (previous_output_cell.clone(), Bytes::new()),
            );

            let witness_data = gen_witness_data(config, &Byte32::new([0; 32]));

            let witness_args = WitnessArgsBuilder::default()
                .lock(Some(witness_data).pack())
                .build();
            tx_builder = tx_builder
                .input(CellInput::new(previous_out_point, 0))
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

pub fn gen_tx_env() -> TxVerifyEnv {
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let header = HeaderView::new_advanced_builder()
        .epoch(epoch.pack())
        .build();
    TxVerifyEnv::new_commit(&header)
}

pub fn gen_consensus() -> Consensus {
    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0032(200)
        .build()
        .unwrap();
    ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build()
}

pub fn debug_printer(_script: &Byte32, msg: &str) {
    print!("{}", msg);
}
