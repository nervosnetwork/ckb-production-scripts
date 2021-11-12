use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_hash::{blake2b_256, Blake2b};
use ckb_script::{TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        hardfork::HardForkSwitch,
        Capacity, DepType, EpochNumberWithFraction, HeaderView, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    packed::{
        Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs, WitnessArgsBuilder,
    },
    prelude::*,
};
use rand::{thread_rng, Rng};
use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree, H256};
use std::{collections::HashMap, convert::TryInto, u128, vec};

pub struct CKBBlake2bHasher(ckb_hash::Blake2b);

pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";

impl Default for CKBBlake2bHasher {
    fn default() -> Self {
        let blake2b = ckb_hash::Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        CKBBlake2bHasher(blake2b)
    }
}

impl sparse_merkle_tree::traits::Hasher for CKBBlake2bHasher {
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

type SMT = SparseMerkleTree<CKBBlake2bHasher, H256, DefaultStore<H256>>;

#[allow(dead_code)]
mod blockchain;

#[allow(dead_code)]
mod compact_udt_mol;

#[allow(dead_code)]
mod xudt_rce_mol;

#[allow(dead_code)]
mod dump_data;
pub use dump_data::*;

mod dummy_data_loader;
use dummy_data_loader::DummyDataLoader;

const MAX_CYCLES: u64 = std::u64::MAX;

////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct Identity([u8; 21]);
impl Identity {
    pub fn as_slice(&self) -> [u8; 21] {
        self.0
    }
}
impl From<Vec<u8>> for Identity {
    fn from(d: Vec<u8>) -> Self {
        assert!(d.len() == 21);
        let ret: [u8; 21] = d.try_into().unwrap_or_else(|v: Vec<u8>| {
            panic!("Expected a Vec of length {} but it was {}", 21, v.len())
        });

        Identity { 0: ret }
    }
}
impl Into<Byte32> for Identity {
    fn into(self) -> Byte32 {
        let mut r: [u8; 32] = [0; 32];
        for i in 0..21 {
            r[i] = self.0[i];
        }
        Byte32::new(r)
    }
}

fn gen_data() -> [u8; 32] {
    let mut buf = [0; 32];
    let mut rng = thread_rng();
    rng.fill(&mut buf);
    buf
}
fn gen_byte32() -> Byte32 {
    Byte32::new(gen_data())
}

// to mol data
fn to_array<T, const N: usize>(d: Vec<T>) -> [T; N] {
    d.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}
fn to_u128(a: u128) -> blockchain::Uint128 {
    blockchain::Uint128::from_slice(&a.to_le_bytes()).unwrap()
}
fn to_scritp_hash(d: &Byte32) -> compact_udt_mol::ScriptHash {
    let d: Vec<molecule::prelude::Byte> = d
        .as_slice()
        .to_vec()
        .into_iter()
        .map(|f| molecule::prelude::Byte::new(f))
        .collect();
    let d = to_array(d);
    compact_udt_mol::ScriptHashBuilder::default().set(d).build()
}
fn to_identity(d: Identity) -> compact_udt_mol::Identity {
    let d =
        d.0.to_vec()
            .into_iter()
            .map(|f| molecule::prelude::Byte::new(f))
            .collect();
    let d = to_array(d);
    compact_udt_mol::IdentityBuilder::default().set(d).build()
}
fn to_signature(d: &[u8]) -> compact_udt_mol::Signature {
    let d = d
        .to_vec()
        .into_iter()
        .map(|f| molecule::prelude::Byte::new(f))
        .collect();
    compact_udt_mol::SignatureBuilder::default().set(d).build()
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
fn to_bytes(d: &Bytes) -> blockchain::Bytes {
    let d: Vec<molecule::prelude::Byte> = d
        .to_vec()
        .into_iter()
        .map(|f| molecule::prelude::Byte::new(f))
        .collect();
    let r = blockchain::BytesBuilder::default();
    let r = r.set(d);
    r.build()
}

#[macro_export]
macro_rules! tx_type_id_eq {
    ($type_id_name: ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $type_id_name(u32);
        impl $type_id_name {
            pub fn new(i: u32) -> Self {
                Self { 0: i }
            }
        }
    };
}
tx_type_id_eq!(ScriptCodeID);
tx_type_id_eq!(UserID);
tx_type_id_eq!(CellID);
tx_type_id_eq!(TransferID);

////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct TXBuilder {
    pub data_loader: DummyDataLoader,

    pub script_codes: HashMap<ScriptCodeID, TXScriptCode>,
    pub script_codes_count: u32,

    pub cudt_scritp_id: Option<ScriptCodeID>,
    pub sudt_scritp_id: Option<ScriptCodeID>,
    pub xudt_scritp_id: Option<ScriptCodeID>,

    pub users: HashMap<UserID, Privkey>,
    pub users_count: u32,

    pub cells: HashMap<CellID, TXCell>,
    pub cells_count: u32,

    pub transfers: HashMap<TransferID, TXTransfer>,
    pub transfer_count: u32,

    pub cudt_hash: Option<Byte32>,

    // test
    pub test_data_rm_user_output: Vec<(CellID, UserID)>,

    // test data
    pub test_data_err_pub_key: bool,
    pub test_data_err_transfer_sign: bool,
}

impl TXBuilder {
    pub fn new() -> TXBuilder {
        TXBuilder {
            data_loader: DummyDataLoader::new(),
            script_codes: HashMap::new(),
            script_codes_count: 0,
            cudt_scritp_id: Option::None,
            sudt_scritp_id: Option::None,
            xudt_scritp_id: Option::None,
            users: HashMap::new(),
            users_count: 0,
            cells: HashMap::new(),
            cells_count: 0,
            transfers: HashMap::new(),
            transfer_count: 0,
            cudt_hash: Option::None,
            test_data_rm_user_output: Vec::new(),
            test_data_err_pub_key: false,
            test_data_err_transfer_sign: false,
        }
    }

    // script
    pub fn add_script_code(mut self, script: (String, Bytes)) -> (Self, ScriptCodeID) {
        let ret = ScriptCodeID::new(self.script_codes_count);
        self.script_codes_count += 1;

        let code_hash = CellOutput::calc_data_hash(&script.1);
        let script = TXScriptCode {
            code: script.1,
            code_hash: code_hash,
            path: script.0,
        };
        self.script_codes.insert(ret, script);
        (self, ret)
    }
    pub fn get_scritp_code(&self, index: ScriptCodeID) -> &Bytes {
        let opt = self.script_codes.get(&index);
        &opt.unwrap().code
    }
    pub fn get_scritp_code_hash(&self, index: ScriptCodeID) -> &Byte32 {
        let opt = self.script_codes.get(&index);
        &opt.unwrap().code_hash
    }
    pub fn set_script_cudt_id(mut self, index: ScriptCodeID) -> Self {
        self.cudt_scritp_id = Option::Some(index);
        self
    }
    pub fn set_scritp_sudt_id(mut self, index: ScriptCodeID) -> Self {
        self.sudt_scritp_id = Option::Some(index);
        self
    }
    pub fn set_scritp_xudt_id(mut self, index: ScriptCodeID) -> Self {
        self.xudt_scritp_id = Option::Some(index);
        self
    }

    // cell
    pub fn add_cell(
        mut self,
        lock_script_id: ScriptCodeID,
        type_script_id: ScriptCodeID,
        enable_identity: bool,
        input_amount: u128,
        output_amount: u128,
        users_info: Vec<TXUser>,
    ) -> (Self, CellID) {
        let cid = CellID::new(self.cells_count);
        self.cells_count += 1;

        let mut cell = TXCell {
            id: cid,
            lock_script_id: lock_script_id,
            type_script_id: type_script_id,
            ver: 0,
            type_id: gen_byte32(),
            identity: Option::None,

            input_amount: input_amount,
            output_amount: output_amount,
            users_info: users_info,

            deposit_vec: Vec::new(),
            transfer_vec: Vec::new(),

            input_kv_pairs: Vec::new(),
            output_kv_pairs: Vec::new(),
            input_hash: Byte32::new([0; 32]),
            output_hash: Byte32::new([0; 32]),
            smt_proof: Bytes::new(),

            lock_script_hash: Byte32::new([0; 32]),

            cell_out_point: Option::None,
            cell_output: Option::None,
        };

        if enable_identity {
            cell.enable_identity();
        }

        self.cells.insert(cid, cell);
        (self, cid)
    }
    pub fn get_cell(&self, index: CellID) -> &TXCell {
        let opt = self.cells.get(&index);
        opt.unwrap()
    }

    // user
    pub fn gen_user(mut self) -> (Self, UserID) {
        let uid = UserID::new(self.users_count);
        self.users_count += 1;

        /*
        let mut key_data: ckb_types::H256 = ckb_types::H256::from([0; 32]);
        key_data.0[0] = self.users_count as u8;
        let user_key = Privkey::from(key_data);
        */
        let user_key = Generator::random_privkey();

        self.users.insert(uid, user_key);
        (self, uid)
    }
    pub fn get_user_key(&self, index: UserID) -> &Privkey {
        let opt = self.users.get(&index);
        opt.unwrap()
    }
    pub fn get_user_identity(&self, index: UserID) -> Identity {
        let privkey = self.get_user_key(index);
        let pubkey = privkey.pubkey().unwrap().serialize();
        let pub_hash = blake2b_256(pubkey.as_slice());
        let mut data = BytesMut::with_capacity(21);
        // Don't test auth, use AuthAlgorithmIdCkb directly here
        data.put_u8(0);

        data.put(Bytes::from(Vec::from(&pub_hash[0..20])));
        Identity::from(data.freeze().to_vec())
    }

    // transfer
    pub fn add_transfer(mut self, t: TXTransfer) -> (Self, TransferID) {
        let s = TransferID::new(self.transfer_count);
        self.transfer_count += 1;
        self.transfers.insert(s, t);
        (self, s)
    }

    pub fn build(&self) -> TX {
        let mut builder: TXBuilder = self.clone();

        // generate transfer and deposit
        builder = builder.gen_transfers_details();
        builder = builder.gen_smt_info();

        let mut tx_builder = TransactionBuilder::default();
        let (builder_tmp, tx_builder_tmp) = builder.add_cell_deps(tx_builder);
        tx_builder = tx_builder_tmp;
        builder = builder_tmp;

        let mut cell_indexs: Vec<CellID> = Vec::new();
        for (_id, cell) in builder.cells.clone() {
            let (builder_tmp, tx_builder_tmp) = builder.build_script(tx_builder, &cell);
            builder = builder_tmp;
            tx_builder = tx_builder_tmp;
        }

        for (_id, cell) in builder.cells.clone() {
            let (builder_tmp, tx_builder_tmp) =
                builder.build_cell(tx_builder, &cell, &mut cell_indexs);
            builder = builder_tmp;
            tx_builder = tx_builder_tmp;
        }
        let tx_view = tx_builder.build();
        let tx_view = builder.sign_cells(tx_view, cell_indexs);
        TX::new(&tx_view, builder)
    }

    // test
    pub fn remove_user_output(mut self, cell_id: u32, user_id: u32) -> Self {
        self.test_data_rm_user_output
            .push((CellID::new(cell_id), UserID::new(user_id)));
        self
    }

    fn add_cell_deps(mut self, builder: TransactionBuilder) -> (Self, TransactionBuilder) {
        let mut builder = builder;
        for (_id, bin) in self.script_codes.clone() {
            if bin.code.len() == 0 {
                return (self, builder);
            }
            let out_point = {
                let contract_tx_hash = { gen_data().pack() };
                OutPoint::new(contract_tx_hash, 0)
            };

            // dep contract code
            let c = CellOutput::new_builder()
                .capacity(
                    Capacity::bytes(bin.code.len())
                        .expect("script capacity")
                        .pack(),
                )
                .build();
            self.data_loader
                .cells
                .insert(out_point.clone(), (c, bin.code.clone()));

            builder = builder.cell_dep(
                CellDep::new_builder()
                    .out_point(out_point)
                    .dep_type(DepType::Code.into())
                    .build(),
            )
        }
        (self, builder)
    }

    fn build_script(
        mut self,
        tx_builder: TransactionBuilder,
        cell: &TXCell,
    ) -> (Self, TransactionBuilder) {
        let previous_tx_hash: Byte32 = gen_byte32();
        let previous_out_point = OutPoint::new(previous_tx_hash, 0);
        let args = self.gen_args(&cell);
        let input_cell_data = self.gen_input_cell_data(&cell);
        let script = Script::new_builder()
            .args(args.pack())
            .code_hash(self.get_scritp_code_hash(cell.lock_script_id).clone())
            .hash_type(ScriptHashType::Data1.into())
            .build();

        let dummy_capacity = Capacity::bytes(input_cell_data.len()).unwrap();
        let previous_output_cell = CellOutput::new_builder()
            .capacity(dummy_capacity.pack())
            .lock(script.clone())
            .build();

        self.data_loader.cells.insert(
            previous_out_point.clone(),
            (previous_output_cell.clone(), input_cell_data),
        );

        let cell_mut = self.cells.get_mut(&cell.id).unwrap();
        cell_mut.lock_script_hash = script.calc_script_hash();
        cell_mut.cell_out_point = Option::Some(previous_out_point);
        cell_mut.cell_output = Option::Some(previous_output_cell);

        if self.cudt_hash.is_none() && cell.lock_script_id == self.cudt_scritp_id.unwrap() {
            self.cudt_hash = Option::Some(script.code_hash());
        }

        (self, tx_builder)
    }

    fn build_cell(
        self,
        tx_builder: TransactionBuilder,
        cell: &TXCell,
        cell_index: &mut Vec<CellID>,
    ) -> (Self, TransactionBuilder) {
        cell_index.push(cell.id);
        let witness = self.gen_cell_witness(cell, Option::None);
        assert!(!witness.is_empty(), "witness is empty");

        let witness_args = WitnessArgsBuilder::default()
            .lock(Some(Bytes::from(witness.to_vec())).pack())
            .build();
        let output_cell_data = self.gen_output_cell_data(&cell);
        let tx_builder = tx_builder
            .input(CellInput::new(
                cell.cell_out_point.clone().unwrap(),
                output_cell_data.len() as u64,
            ))
            .witness(witness_args.as_bytes().pack());
        let tx_builder = tx_builder
            .output(cell.cell_output.clone().unwrap())
            .output_data(output_cell_data.pack());
        (self, tx_builder)
    }

    fn gen_transfers_details(mut self) -> Self {
        for (_id, tx) in self.transfers.clone() {
            let witness_t = WitnessTransfer {
                source: tx.source_id,
                target_type: tx.target_type,
                target_cell: tx.target_cell,
                target_id: tx.target_id,
                amount: tx.amount,
                fee: tx.fee,
            };
            let source_cell = self.cells.get_mut(&tx.source_cell).unwrap();
            source_cell.transfer_vec.push(witness_t);

            let witness_d = WitnessDeposit {
                source: tx.source_cell,
                target: tx.target_id,
                amount: tx.amount,
                fee: tx.fee,
            };
            let target_cell = self.cells.get_mut(&tx.target_cell).unwrap();
            target_cell.deposit_vec.push(witness_d);
        }
        self
    }
    fn gen_kv_users(mut self, cell: TXCell, id: CellID, user: &TXUser) -> Self {
        let identity = self.get_user_identity(user.index);

        let mut nonce = user.nonce;
        let kv_pair = WitnessKVPair {
            index: user.index,
            identity: identity.clone(),
            amount: user.amount,
            nonce: nonce,
        };
        let cell_mut = self.cells.get_mut(&id).unwrap();
        cell_mut.input_kv_pairs.push(kv_pair.clone());

        let mut amount: u128 = user.amount;
        for deposit in &cell.deposit_vec {
            if deposit.source == cell.id {
                continue;
            }
            if deposit.target == user.index {
                amount += deposit.amount;
            }
        }

        for transfer in &cell.transfer_vec {
            if transfer.source == user.index {
                if transfer.amount > amount {
                    amount = 0;
                } else {
                    amount -= transfer.amount;
                }

                if transfer.fee > amount {
                    amount = 0;
                } else {
                    amount -= transfer.fee;
                }

                if nonce == 0xffffffff {
                    nonce = 0;
                } else {
                    nonce += 1;
                }
            }
            if transfer.target_type == WitnessTransferTargetType::Identity
                && transfer.target_id == user.index
            {
                amount += transfer.amount;
            }
        }
        let kv_pair = WitnessKVPair {
            index: user.index,
            identity: identity,
            amount: amount,
            nonce: nonce,
        };
        let cell_mut = self.cells.get_mut(&id).unwrap();

        for (cell_id, user_id) in self.test_data_rm_user_output.clone() {
            if cell_id == cell.id && user_id == user.index {
                return self;
            }
        }

        cell_mut.output_kv_pairs.push(kv_pair.clone());
        self
    }
    fn gen_kv_info(mut self, cell: TXCell, id: CellID) -> Self {
        if cell.lock_script_id != self.cudt_scritp_id.unwrap() {
            return self;
        }
        for user in &cell.users_info {
            self = self.gen_kv_users(cell.clone(), id, user);
        }
        self
    }
    fn gen_smt_info(mut self) -> Self {
        for (id, cell) in self.cells.clone() {
            self = self.gen_kv_info(cell, id);
        }

        for (id, cell) in self.cells.clone() {
            if cell.lock_script_id != self.cudt_scritp_id.unwrap() {
                continue;
            }
            let mut smt = SMT::default();
            let mut keys: Vec<H256> = Vec::new();
            let mut leaves: Vec<(H256, H256)> = Vec::new();
            for user in &cell.input_kv_pairs {
                let (k, v) = Self::get_kv(user);
                smt.update(k, v).expect("smt update input kv failed");
                keys.push(k);
                leaves.push((k, v));
            }
            let cell_mut = self.cells.get_mut(&id).unwrap();
            let input_hash = smt.root();
            cell_mut.input_hash = Byte32::from_slice(input_hash.as_slice()).unwrap();

            let proof = smt
                .merkle_proof(keys)
                .expect("smt merkle proof failed")
                .compile(leaves)
                .unwrap();
            let bin_proof: Vec<u8> = proof.clone().into();
            cell_mut.smt_proof = Bytes::from(bin_proof);

            //let mut leaves: Vec<(H256, H256)> = Vec::new();
            let mut smt = SMT::default();
            for user in &cell.output_kv_pairs {
                let (k, v) = Self::get_kv(user);
                smt.update(k, v).expect("smt update input kv failed");
            }
            cell_mut.output_hash = Byte32::from_slice(smt.root().as_slice()).unwrap();
        }
        self
    }
    fn get_kv(kv_pair: &WitnessKVPair) -> (H256, H256) {
        let key: Byte32 = kv_pair.identity.clone().into();
        let mut val = BytesMut::with_capacity(32);
        val.put_u128_le(kv_pair.amount);
        val.put_u32_le(kv_pair.nonce);
        val.put(Bytes::from([0; 12].to_vec()));
        let k: [u8; 32] = key.unpack();
        let v: [u8; 32] = Byte32::from_slice(val.freeze().to_vec().as_slice())
            .unwrap()
            .unpack();
        (H256::from(k), H256::from(v))
    }

    fn gen_args(&self, cell: &TXCell) -> Bytes {
        let mut args_len = 1 + 32; // u8(ver) + hash(32)
        if cell.identity.is_some() {
            args_len += 21; // identity size
        }

        let mut args = BytesMut::with_capacity(args_len);

        // version
        args.put_u8(cell.ver);

        // type id
        args.put(cell.type_id.as_bytes());

        // identity
        if cell.identity.is_some() {
            let pubkey = cell
                .identity
                .clone()
                .unwrap()
                .pubkey()
                .expect("args identity pubkey");
            let mut pub_hash = blake2b_256(pubkey.serialize().as_slice());
            if self.test_data_err_pub_key {
                pub_hash = gen_data();
            }
            let mut data = BytesMut::with_capacity(21);
            data.put_u8(0);
            data.put(Bytes::from(Vec::from(&pub_hash[0..20])));
            args.put(data.freeze());
        }

        args.freeze()
    }
    fn gen_input_cell_data(&self, cell: &TXCell) -> Bytes {
        self.gen_cell_data(cell, &cell.input_amount, &cell.input_hash)
    }
    fn gen_output_cell_data(&self, cell: &TXCell) -> Bytes {
        self.gen_cell_data(cell, &cell.output_amount, &cell.output_hash)
    }
    fn gen_cell_data(&self, cell: &TXCell, amount: &u128, hash: &Byte32) -> Bytes {
        let mut data = BytesMut::with_capacity(256);
        data.put_u128_le(amount.clone());

        if self.sudt_scritp_id.unwrap() == cell.type_script_id {
            data.put_u32_le(0xFFFFFFFF);
            data.put(hash.as_bytes());
            data.freeze()
        } else if self.xudt_scritp_id.unwrap() == cell.type_script_id {
            self.gen_xudt_cell_data(amount, hash)
        } else {
            assert!(false, "unknow type script");
            Bytes::new()
        }
    }
    fn gen_xudt_cell_data(&self, amount: &u128, hash: &Byte32) -> Bytes {
        let mut xudt_builder = xudt_rce_mol::XudtDataBuilder::default();

        let data = Bytes::from([0; 32].to_vec());
        let mut bc_builder = blockchain::BytesVecBuilder::default();
        bc_builder = bc_builder.push(to_bytes(&data));

        xudt_builder = xudt_builder.lock(to_bytes(&hash.as_bytes()));
        xudt_builder = xudt_builder.data(bc_builder.build());

        let xudt_data = xudt_builder.build().as_bytes();

        let mut ret = BytesMut::with_capacity(xudt_data.len() + 16);
        ret.put_u128_le(*amount);
        ret.put(xudt_data);

        ret.freeze()
    }

    // witness
    fn gen_cell_witness(&self, cell: &TXCell, sign_data: Option<Bytes>) -> Bytes {
        let mut deposit_vec = compact_udt_mol::DepositVecBuilder::default();
        for d in &cell.deposit_vec {
            if d.source == cell.id {
                continue;
            }
            let c = self.get_cell(d.source);

            let depoist = compact_udt_mol::DepositBuilder::default()
                .source(to_scritp_hash(&c.lock_script_hash))
                .target(to_identity(self.get_user_identity(d.target)))
                .amount(to_u128(d.amount))
                .fee(to_u128(d.fee))
                .build();
            deposit_vec = deposit_vec.push(depoist);
        }

        let mut transfer_vec = compact_udt_mol::TransferVecBuilder::default();
        for t in &cell.transfer_vec {
            let mut transfer_tag = compact_udt_mol::TransferTargetBuilder::default();
            match t.target_type {
                WitnessTransferTargetType::None => {
                    assert!(false);
                }
                WitnessTransferTargetType::ScritpHash => {
                    let hash = to_scritp_hash(&self.get_cell(t.target_cell).lock_script_hash);
                    transfer_tag = transfer_tag.set(hash);
                }
                WitnessTransferTargetType::Identity => {
                    let id = to_identity(self.get_user_identity(t.target_id));
                    transfer_tag = transfer_tag.set(id);
                }
                WitnessTransferTargetType::Between => {
                    let mut between = compact_udt_mol::MoveBetweenCompactSMTBuilder::default();
                    between = between.identity(to_identity(self.get_user_identity(t.target_id)));
                    between = between.script_hash(to_scritp_hash(
                        &self.get_cell(t.target_cell).lock_script_hash,
                    ));
                    transfer_tag = transfer_tag.set(between.build());
                }
            }
            let id = self.get_user_identity(t.source);
            let transfer_raw = compact_udt_mol::RawTransferBuilder::default()
                .source(to_identity(id))
                .target(transfer_tag.build())
                .amount(to_u128(t.amount))
                .fee(to_u128(t.fee))
                .build();

            let mut b2b: Blake2b = ckb_hash::new_blake2b();
            b2b.update(cell.type_id.as_slice());
            b2b.update(&cell.get_user_input_nonce(t.source).to_le_bytes());
            b2b.update(transfer_raw.as_slice());
            let mut message = [0; 32];
            b2b.finalize(&mut message);

            if self.test_data_err_transfer_sign {
                message = gen_data();
            }
            let key = self.get_user_key(t.source);
            let sign = key
                .sign_recoverable(&ckb_types::H256::from(message))
                .unwrap();

            let transfer = compact_udt_mol::TransferBuilder::default()
                .raw(transfer_raw)
                .signature(to_signature(&sign.serialize()))
                .build();
            transfer_vec = transfer_vec.push(transfer);
        }

        let mut kv_pairs = compact_udt_mol::KVPairVecBuilder::default();
        for kv in &cell.input_kv_pairs {
            let key: Byte32 = kv.identity.clone().into();
            let mut val = BytesMut::with_capacity(32);
            val.put_u128_le(kv.amount);
            val.put_u32_le(kv.nonce);
            val.put(Bytes::from([0; 12].to_vec()));
            let val = Byte32::from_slice(val.freeze().to_vec().as_slice()).unwrap();

            kv_pairs = kv_pairs.push(
                compact_udt_mol::KVPairBuilder::default()
                    .k(to_byte32(&key))
                    .v(to_byte32(&val))
                    .build(),
            );
        }

        let kv_proof: blockchain::Bytes = to_bytes(&cell.smt_proof);
        let mut witness = compact_udt_mol::CompactUDTEntriesBuilder::default()
            .deposits(deposit_vec.build())
            .transfers(transfer_vec.build())
            .kv_state(kv_pairs.build())
            .kv_proof(kv_proof);
        if cell.identity.is_some() {
            let sign: Bytes;
            if sign_data.is_none() {
                sign = Bytes::from([0; 65].to_vec());
            } else {
                sign = sign_data.unwrap();
            }
            witness = witness.signature(
                compact_udt_mol::SignatureOptBuilder::default()
                    .set(Option::Some(to_signature(sign.to_vec().as_slice())))
                    .build(),
            );
        }

        witness.build().as_bytes()
    }
    fn sign_cells(&self, tx: TransactionView, cell_indexs: Vec<CellID>) -> TransactionView {
        //let len = tx.witnesses().len();
        let mut signed_witnesses: Vec<ckb_types::packed::Bytes> = tx
            .inputs()
            .into_iter()
            .enumerate()
            .map(|(i, _cell_input)| {
                let cell = self.get_cell(cell_indexs[i]);
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                if cell.identity.is_none() {
                    return witness.as_bytes().pack();
                }

                let sign_data = self.sign_cell(i, 1, &tx, cell, &witness.as_bytes());
                let data = self.gen_cell_witness(cell, Option::Some(sign_data));
                witness
                    .as_builder()
                    .lock(Some(data).pack())
                    .build()
                    .as_bytes()
                    .pack()
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
    fn sign_cell(
        &self,
        i: usize,
        len: usize,
        tx: &TransactionView,
        cell: &TXCell,
        witness: &Bytes,
    ) -> Bytes {
        let mut b2b = ckb_hash::new_blake2b();

        // tx hash
        b2b.update(tx.hash().as_slice());

        // witness len
        let witness_len: u64 = witness.len() as u64;
        b2b.update(&witness_len.to_le_bytes());
        let witness = WitnessArgs::new_unchecked(witness.clone());
        let zero_lock: Bytes = {
            let mut buf = Vec::new();
            buf.resize((witness_len - 20) as usize, 0);
            buf.into()
        };
        let witness_for_digest = witness
            .clone()
            .as_builder()
            .lock(Some(zero_lock).pack())
            .build();

        b2b.update(&witness_for_digest.as_bytes());

        ((i + 1)..(i + len)).for_each(|n| {
            let witness = tx.witnesses().get(n).unwrap();
            let witness_len = witness.raw_data().len() as u64;
            b2b.update(&witness_len.to_le_bytes());
            b2b.update(&witness.raw_data());
        });

        let mut message = [0; 32];
        b2b.finalize(&mut message);

        let key = cell.identity.clone().unwrap();
        let sign = Bytes::from(
            key.sign_recoverable(&ckb_types::H256(message))
                .unwrap()
                .serialize(),
        );
        sign
    }
}

////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct TXScriptCode {
    pub code: Bytes,
    pub code_hash: Byte32,
    pub path: String,
}

#[derive(Clone)]
pub struct TXCell {
    pub id: CellID,
    pub lock_script_id: ScriptCodeID,
    pub type_script_id: ScriptCodeID,
    pub ver: u8,
    pub type_id: Byte32,
    pub identity: Option<Privkey>,

    pub input_amount: u128,
    pub output_amount: u128,
    pub users_info: Vec<TXUser>,

    pub deposit_vec: Vec<WitnessDeposit>,
    pub transfer_vec: Vec<WitnessTransfer>,
    pub input_kv_pairs: Vec<WitnessKVPair>,
    pub output_kv_pairs: Vec<WitnessKVPair>,
    pub input_hash: Byte32,
    pub output_hash: Byte32,
    pub smt_proof: Bytes,

    pub lock_script_hash: Byte32,

    pub cell_out_point: Option<OutPoint>,
    pub cell_output: Option<CellOutput>,
}

impl TXCell {
    pub fn get_user_input_nonce(&self, index: UserID) -> u32 {
        for u in &self.input_kv_pairs {
            if u.index == index {
                return u.nonce;
            }
        }
        0xFFFFFFFF
    }
    pub fn enable_identity(&mut self) {
        self.identity = Option::Some(Generator::random_privkey());
    }
}

#[derive(Clone)]
pub struct TXUser {
    pub index: UserID,
    pub nonce: u32,
    pub amount: u128,
}

#[derive(Clone)]
pub struct TXTransfer {
    pub source_cell: CellID,
    pub source_id: UserID,
    pub target_cell: CellID,
    pub target_id: UserID,
    pub target_type: WitnessTransferTargetType,
    pub amount: u128,
    pub fee: u128,
}

#[derive(Clone)]
pub struct WitnessDeposit {
    pub source: CellID,
    pub target: UserID,
    pub amount: u128,
    pub fee: u128,
}

#[derive(Clone, PartialEq, Eq)]
pub enum WitnessTransferTargetType {
    None,
    ScritpHash,
    Identity,
    Between,
}

#[derive(Clone)]
pub struct WitnessTransfer {
    pub source: UserID,
    pub target_cell: CellID,
    pub target_id: UserID,
    pub target_type: WitnessTransferTargetType,
    pub amount: u128,
    pub fee: u128,
}

#[derive(Clone)]
pub struct WitnessKVPair {
    pub index: UserID,
    pub identity: Identity,
    pub amount: u128,
    pub nonce: u32,
}

pub struct TX {
    pub resolved_tx: ResolvedTransaction,
    pub data_loader: DummyDataLoader,
    tx_backup: TransactionView,
    data_loader_backup: DummyDataLoader,
    cudt_hash: Byte32,
    deps_info: Vec<TXScriptCode>,

    pub builder: TXBuilder,
}

impl TX {
    pub fn new(tx: &TransactionView, builder: TXBuilder) -> TX {
        let data_loader_backup = builder.data_loader.clone();
        let resolved_cell_deps = tx
            .cell_deps()
            .into_iter()
            .map(|deps_out_point| {
                let (dep_output, dep_data) = builder
                    .data_loader
                    .cells
                    .get(&deps_out_point.out_point())
                    .unwrap();
                CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                    .out_point(deps_out_point.out_point())
                    .build()
            })
            .collect();

        let mut resolved_inputs = Vec::new();
        for i in 0..tx.inputs().len() {
            let previous_out_point = tx.inputs().get(i).unwrap().previous_output();
            let (input_output, input_data) =
                builder.data_loader.cells.get(&previous_out_point).unwrap();
            resolved_inputs.push(
                CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
                    .out_point(previous_out_point)
                    .build(),
            );
        }
        let cudt_hash = builder.cudt_hash.clone().unwrap();
        let deps_info = builder
            .script_codes
            .clone()
            .into_iter()
            .map(|(_id, sc)| sc.clone())
            .collect();
        TX {
            resolved_tx: ResolvedTransaction {
                transaction: tx.clone(),
                resolved_cell_deps,
                resolved_inputs,
                resolved_dep_groups: vec![],
            },
            data_loader: DummyDataLoader::new(),
            tx_backup: tx.clone(),
            data_loader_backup,
            cudt_hash,
            deps_info,
            builder,
        }
    }

    pub fn run(&self) -> Result<u64, ckb_error::Error> {
        let consensus = TX::gen_consensus();
        let tx_env = TX::gen_tx_env();
        let mut verifier = TransactionScriptsVerifier::new(
            &self.resolved_tx,
            &consensus,
            &self.data_loader,
            &tx_env,
        );
        verifier.set_debug_printer(TX::debug_printer);
        let ret = verifier.verify(MAX_CYCLES);

        ret
    }

    pub fn output_ctrl(&self, name: &str) {
        let data = dump_data(
            self.tx_backup.clone(),
            name.into(),
            self.data_loader_backup.clone(),
            self.cudt_hash.clone(),
            self.deps_info.clone(),
        );
        data.output_ctrl();
    }

    pub fn output_json(&self, name: &str) {
        let data = dump_data(
            self.tx_backup.clone(),
            name.into(),
            self.data_loader_backup.clone(),
            self.cudt_hash.clone(),
            self.deps_info.clone(),
        );
        data.output_json();
    }

    fn debug_printer(_script: &Byte32, msg: &str) {
        print!("{}", msg);
    }

    fn gen_tx_env() -> TxVerifyEnv {
        let epoch = EpochNumberWithFraction::new(300, 0, 1);
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    }

    fn gen_consensus() -> Consensus {
        let hardfork_switch = HardForkSwitch::new_without_any_enabled()
            .as_builder()
            .rfc_0232(200)
            .build()
            .unwrap();
        ConsensusBuilder::default()
            .hardfork_switch(hardfork_switch)
            .build()
    }
}
