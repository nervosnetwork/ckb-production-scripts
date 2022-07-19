use ckb_hash::Blake2b;
use ckb_types::bytes::{BufMut, BytesMut};
use ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{CellOutput, Script},
    prelude::*,
};
use rand::prelude::thread_rng;
use rand::Rng;

use super::ckb_sys_call::*;
use super::dummy_data_loader::DummyDataLoader;

#[derive(Copy, Clone)]
pub enum OpentxCommand {
    TxHash = 0x00,
    GroupInputOutputLen = 0x01,
    IndexOutput = 0x11,
    OffsetOutput = 0x12,
    IndexInput = 0x13,
    OffsetInput = 0x14,
    CellInputIndex = 0x15,
    CellInputOffset = 0x16,
    ConcatArg1Arg2 = 0x20,
    End = 0xF0,

    ErrorCmd = 0xAB,
}

pub const CELL_MASK_CAPACITY: u32 = 0x1;
pub const CELL_MASK_LOCK_CODE_HASH: u32 = 0x2;
pub const CELL_MASK_LOCK_HASH_TYPE: u32 = 0x4;
pub const CELL_MASK_LOCK_ARGS: u32 = 0x8;
pub const CELL_MASK_TYPE_CODE_HASH: u32 = 0x10;
pub const CELL_MASK_TYPE_HASH_TYPE: u32 = 0x20;
pub const CELL_MASK_TYPE_ARGS: u32 = 0x40;
pub const CELL_MASK_CELL_DATA: u32 = 0x80;
pub const CELL_MASK_TYPE_SCRIPT_HASH: u32 = 0x100;
pub const CELL_MASK_LOCK_SCRIPT_HASH: u32 = 0x200;
pub const CELL_MASK_WHOLE_CELL: u32 = 0x400;

pub const INPUT_MASK_TX_HASH: u32 = 0x1;
pub const INPUT_MASK_INDEX: u32 = 0x2;
pub const INPUT_MASK_SINCE: u32 = 0x4;
pub const INPUT_MASK_PREVIOUS_OUTPUT: u32 = 0x8;
pub const INPUT_MASK_WHOLE: u32 = 0x10;

#[derive(Clone)]
pub struct OpentxSigInput {
    pub cmd: OpentxCommand,
    pub arg1: u32,
    pub arg2: u32,
}

#[derive(Clone)]
pub struct OpentxWitness {
    pub base_input_index: usize,
    pub base_output_index: usize,
    pub input: Vec<OpentxSigInput>,

    pub err_witness_short: bool,
    pub err_witness_rand: bool,
    pub err_sign: bool,
    pub has_output_type_script: bool,
}

impl OpentxWitness {
    pub fn new(input_index: usize, output_index: usize, input: Vec<OpentxSigInput>) -> Self {
        OpentxWitness {
            base_input_index: input_index,
            base_output_index: output_index,
            input,
            err_witness_short: false,
            err_witness_rand: false,
            err_sign: false,
            has_output_type_script: true,
        }
    }

    pub fn get_opentx_sig_len(&self) -> usize {
        4 + 4 + 4 * self.input.len()
    }
}

struct OpentxCache {
    blake2b: Blake2b,
}

impl OpentxCache {
    pub fn new() -> Self {
        OpentxCache {
            blake2b: ckb_hash::new_blake2b(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.blake2b.update(data);
        // dbg_print_bytes(&data.to_vec(), -1, "== update hash");
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut msg = [0u8; 32];
        self.blake2b.finalize(&mut msg);
        msg
    }
}

fn get_cell(ckb_sys_call: &CkbSysCall, index: usize, is_input: bool) -> Option<CellOutput> {
    if is_input {
        let cell = ckb_sys_call.transaction.inputs().get(index);
        if cell.is_none() {
            Option::None
        } else {
            let cell = ckb_sys_call
                .dummy
                .cells
                .get(&cell.unwrap().previous_output());
            if cell.is_none() {
                Option::None
            } else {
                Option::Some(cell.unwrap().0.clone())
            }
        }
    } else {
        ckb_sys_call.transaction.output(index)
    }
}

fn hash_cell(
    cache: &mut OpentxCache,
    ckb_sys_call: &CkbSysCall,
    si: &OpentxSigInput,
    is_input: bool,
    with_offset: bool,
    base_index: usize,
) {
    let mut index = si.arg1 as usize;
    if with_offset {
        index += base_index
    }
    let source = if is_input {
        CkbSysCallSource::Input
    } else {
        CkbSysCallSource::Outpout
    };
    if si.arg2 & CELL_MASK_CAPACITY != 0 {
        let data =
            ckb_sys_call.sys_load_cell_by_field(index, source, CkbSysCallCellField::Capacity);
        if data.is_ok() {
            cache.update(&data.clone().ok().unwrap());
        }
    }
    if si.arg2 & CELL_MASK_LOCK_CODE_HASH != 0 {
        let cell = get_cell(&ckb_sys_call, index, is_input);
        if cell.is_some() {
            let cell = cell.unwrap();
            cache.update(&cell.lock().code_hash().as_slice().to_vec());
        }
    }
    if si.arg2 & CELL_MASK_LOCK_HASH_TYPE != 0 {
        let cell = get_cell(&ckb_sys_call, index, is_input);
        if cell.is_some() {
            let cell = cell.unwrap();
            let hash_type = cell.lock().hash_type();
            cache.update(hash_type.as_slice());
        }
    }
    if si.arg2 & CELL_MASK_LOCK_ARGS != 0 {
        let cell = get_cell(&ckb_sys_call, index, is_input);
        if cell.is_some() {
            let cell = cell.unwrap();
            let args = cell.lock().args().as_slice().split_at(4).1.to_vec();
            cache.update(args.as_slice());
        }
    }

    if si.arg2 & CELL_MASK_TYPE_CODE_HASH != 0 {
        let cell = get_cell(&ckb_sys_call, index, is_input);
        if cell.is_some() && cell.clone().unwrap().type_().is_some() {
            let cell = cell.unwrap();
            let type_cell = Script::from_slice(cell.type_().as_slice()).unwrap();
            cache.update(&type_cell.code_hash().as_slice());
        }
    }
    if si.arg2 & CELL_MASK_TYPE_HASH_TYPE != 0 {
        let cell = get_cell(&ckb_sys_call, index, is_input);
        if cell.is_some() && cell.clone().unwrap().type_().is_some() {
            let cell = cell.unwrap();
            let cell_type = Script::from_slice(cell.type_().as_slice()).unwrap();
            let hash_type = cell_type.hash_type();
            cache.update(hash_type.as_slice());
        }
    }
    if si.arg2 & CELL_MASK_TYPE_ARGS != 0 {
        let cell = get_cell(&ckb_sys_call, index, is_input);
        if cell.is_some() && cell.clone().unwrap().type_().is_some() {
            let cell = cell.unwrap();
            let cell_type = Script::from_slice(cell.type_().as_slice()).unwrap();
            let args = cell_type.args().as_slice().split_at(4).1.to_vec();
            cache.update(&args);
        }
    }
    if si.arg2 & CELL_MASK_CELL_DATA != 0 {
        let data = ckb_sys_call.sys_load_cell_data(index, source);
        if data.is_ok() {
            cache.update(data.clone().ok().unwrap().as_slice());
        }
    }

    if si.arg2 & CELL_MASK_TYPE_SCRIPT_HASH != 0 {
        let cell = get_cell(&ckb_sys_call, index, is_input);
        if cell.is_some() && cell.clone().unwrap().type_().is_some() {
            let cell = cell.unwrap();
            let cell_type = Script::from_slice(cell.type_().as_slice()).unwrap();
            let hash = cell_type.calc_script_hash();
            cache.update(hash.as_slice());
        }
    }

    if si.arg2 & CELL_MASK_LOCK_SCRIPT_HASH != 0 {
        let cell = get_cell(&ckb_sys_call, index, is_input);
        if cell.is_some() {
            let hash = cell.unwrap().lock().calc_script_hash();
            cache.update(hash.as_slice());
        }
    }

    if si.arg2 & CELL_MASK_WHOLE_CELL != 0 {
        let data = ckb_sys_call.sys_load_cell(index, source);
        if data.is_ok() {
            cache.update(data.clone().ok().unwrap().as_slice());
        }
    }
}

fn hash_input(
    cache: &mut OpentxCache,
    ckb_sys_call: &CkbSysCall,
    si: &OpentxSigInput,
    with_offset: bool,
    base_index: usize,
) {
    let index = if with_offset {
        si.arg1 as usize + base_index
    } else {
        si.arg1 as usize
    };

    if (si.arg2 & INPUT_MASK_TX_HASH) != 0 {
        let cell = ckb_sys_call.transaction.inputs().get(index);
        if cell.is_some() {
            let cell = cell.unwrap();
            let data = cell.previous_output().tx_hash();
            cache.update(&data.as_slice());
        }
    }

    if (si.arg2 & INPUT_MASK_INDEX) != 0 {
        let cell = ckb_sys_call.transaction.inputs().get(index);
        if cell.is_some() {
            let cell = cell.unwrap();
            let data = cell.previous_output().index();
            cache.update(data.as_slice());
        }
    }

    if (si.arg2 & INPUT_MASK_SINCE) != 0 {
        let data = ckb_sys_call.sys_load_input_by_field(
            index,
            CkbSysCallSource::Input,
            CkbSysCallInputField::Since,
        );

        if data.is_ok() {
            let data = data.ok().unwrap();
            cache.update(&data);
        }
    }

    if (si.arg2 & INPUT_MASK_PREVIOUS_OUTPUT) != 0 {
        let data = ckb_sys_call.sys_load_input_by_field(
            index,
            CkbSysCallSource::Input,
            CkbSysCallInputField::OutPoint,
        );

        if data.is_ok() {
            let data = data.ok().unwrap();
            cache.update(&data);
        }
    }

    if (si.arg2 & INPUT_MASK_WHOLE) != 0 {
        let data = ckb_sys_call.sys_load_input(index, CkbSysCallSource::Input);
        if data.is_ok() {
            let data = data.ok().unwrap();
            cache.update(&data);
        }
    }
}

fn calc_group_len(is_input: bool, ckb_sys_call: &CkbSysCall) -> u64 {
    let mut index = 0;
    loop {
        let source = if is_input {
            CkbSysCallSource::GroupInput
        } else {
            CkbSysCallSource::GroupOutpout
        };
        let ret = ckb_sys_call.sys_load_cell_by_field(index, source, CkbSysCallCellField::Capacity);
        if ret.is_err() {
            break;
        }
        index += 1;
    }

    index as u64
}

pub fn get_opentx_message(
    dummy: &mut DummyDataLoader,
    tx: &TransactionView,
    _: usize, // index
    opentx_sig_input: &OpentxWitness,
) -> ([u8; 32], Bytes) {
    let ckb_sys_call = CkbSysCall::new(tx, &dummy);

    let mut cache = OpentxCache::new();
    let mut s_data = BytesMut::with_capacity(opentx_sig_input.input.len() * 4);
    for si in &opentx_sig_input.input {
        match si.cmd {
            OpentxCommand::TxHash => {
                let tx_hash = ckb_sys_call.sys_load_tx_hash();
                cache.update(tx_hash.as_slice());
            }
            OpentxCommand::GroupInputOutputLen => {
                cache.update(&calc_group_len(true, &ckb_sys_call).to_le_bytes());
                cache.update(&calc_group_len(false, &ckb_sys_call).to_le_bytes());
            }
            OpentxCommand::IndexOutput => {
                hash_cell(&mut cache, &ckb_sys_call, &si, false, false, 0);
            }
            OpentxCommand::OffsetOutput => {
                hash_cell(
                    &mut cache,
                    &ckb_sys_call,
                    &si,
                    false,
                    true,
                    opentx_sig_input.base_output_index,
                );
            }
            OpentxCommand::IndexInput => {
                hash_cell(&mut cache, &ckb_sys_call, &si, true, false, 0);
            }
            OpentxCommand::OffsetInput => {
                hash_cell(
                    &mut cache,
                    &ckb_sys_call,
                    &si,
                    true,
                    true,
                    opentx_sig_input.base_input_index,
                );
            }
            OpentxCommand::CellInputIndex => {
                hash_input(&mut cache, &ckb_sys_call, &si, false, 0);
            }
            OpentxCommand::CellInputOffset => {
                hash_input(
                    &mut cache,
                    &ckb_sys_call,
                    &si,
                    true,
                    opentx_sig_input.base_input_index,
                );
            }
            OpentxCommand::ConcatArg1Arg2 => {
                let data = (si.arg1 & 0xfff) | ((si.arg2 & 0xfff) << 12);
                let data = data.to_le_bytes();
                cache.update(&data[0..3]);
            }
            OpentxCommand::End => {}
            OpentxCommand::ErrorCmd => {
                // is errror
            }
        }

        let s: u32 = (si.cmd as u32) + (si.arg1 << 8) + (si.arg2 << 20);
        s_data.put_u32_le(s);
    }

    let s_data = s_data.freeze();
    cache.update(s_data.to_vec().as_slice());

    let msg = cache.finalize();
    (msg, s_data)
}

pub fn get_opentx_sig(
    opentx_sig_input: &OpentxWitness,
    sil_data: Bytes,
    sig_bytes: Bytes,
) -> Bytes {
    let mut rng = thread_rng();

    if opentx_sig_input.err_witness_short {
        Bytes::from([0u8; 7].to_vec())
    } else if opentx_sig_input.err_witness_rand {
        let mut data = Vec::<u8>::new();
        data.resize(rng.gen_range(9, 128) as usize, 0);
        rng.fill(data.as_mut_slice());
        Bytes::from(data.to_vec())
    } else {
        let mut data =
            BytesMut::with_capacity(opentx_sig_input.get_opentx_sig_len() + sig_bytes.len());
        data.put_u32_le(opentx_sig_input.base_input_index as u32);
        data.put_u32_le(opentx_sig_input.base_output_index as u32);

        data.put(sil_data);

        if opentx_sig_input.err_sign {
            let mut sign = Vec::<u8>::new();
            sign.resize(sig_bytes.len(), 0);
            rng.fill(sign.as_mut_slice());

            data.put(Bytes::from(sign))
        } else {
            data.put(sig_bytes);
        }
        data.freeze()
    }
}
