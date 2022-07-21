#![allow(unused_imports)]

use ckb_hash::blake2b_256;
use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionView},
    packed::{Byte32, CellOutput, OutPoint, Script},
    prelude::Entity,
};
use std::{cmp::Ordering, collections::HashMap, option};

use super::dummy_data_loader::DummyDataLoader;

pub struct CkbSysCall {
    pub transaction: TransactionView,
    pub dummy: DummyDataLoader,

    group_index: Vec<(bool, usize)>, // is input / index

    script_hash: Byte32,
    is_type: bool,
}

#[derive(Copy, Clone, PartialEq)]
pub enum CkbSysCallSource {
    Input,
    GroupInput,
    Outpout,
    GroupOutpout,
    CellDep,
}

#[derive(Copy, Clone)]
pub enum CkbSysCallCellField {
    Capacity,
    DataHash,
    Lock,
    LockHash,
    Type,
    TypeHash,
    OccupiedCapacity,
}

#[derive(Copy, Clone)]
pub enum CkbSysCallInputField {
    OutPoint,
    Since,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum CkbSysCallError {
    Success = 0,
    OutOfBound = 1,
    ItemMissing = 2,
    LengthNotEnough = 3,
    InvalidData = 4,
}

impl CkbSysCall {
    pub fn new(
        transaction: &TransactionView,
        dummy: &DummyDataLoader,
        script_hash: Byte32,
        is_type: bool,
    ) -> Self {
        let mut group_index = Vec::<(bool, usize)>::new();
        if !is_type {
            // all lock
            for index in 0..transaction.inputs().len() {
                let lock_hash = dummy
                    .cells
                    .get(&transaction.inputs().get(index).unwrap().previous_output())
                    .unwrap()
                    .0
                    .lock()
                    .calc_script_hash();
                if lock_hash.cmp(&script_hash) == Ordering::Equal {
                    group_index.push((true, index));
                }
            }
        } else {
            for index in 0..transaction.inputs().len() {
                let type_script = dummy
                    .cells
                    .get(&transaction.inputs().get(index).unwrap().previous_output())
                    .unwrap()
                    .0
                    .type_();
                if type_script.is_none() {
                    continue;
                }

                let type_script = Script::from_slice(type_script.as_slice()).unwrap();
                if type_script.calc_script_hash().cmp(&script_hash) == Ordering::Equal {
                    group_index.push((true, index));
                }
            }

            for index in 0..transaction.outputs().len() {
                let type_script = transaction.output(index).unwrap().type_();
                if type_script.is_none() {
                    continue;
                }

                let type_script = Script::from_slice(type_script.as_slice()).unwrap();
                if type_script.calc_script_hash().cmp(&script_hash) == Ordering::Equal {
                    group_index.push((false, index));
                }
            }
        }
        assert!(!group_index.is_empty());

        CkbSysCall {
            transaction: transaction.clone(),
            dummy: dummy.clone(),
            group_index,

            script_hash,
            is_type,
        }
    }

    fn get_input_cell(&self, index: usize) -> Result<&(CellOutput, Bytes), CkbSysCallError> {
        let input = self.transaction.inputs().get(index);
        if input.is_none() {
            Result::Err(CkbSysCallError::OutOfBound)
        } else {
            Result::Ok(
                self.dummy
                    .cells
                    .get(&input.unwrap().previous_output())
                    .unwrap(),
            )
        }
    }

    fn get_output_cell(&self, index: usize) -> Option<CellOutput> {
        self.transaction.output(index)
    }

    pub fn sys_load_tx_hash(&self) -> Byte32 {
        self.transaction.hash()
    }

    pub fn sys_load_transaction(&self) -> Vec<u8> {
        self.transaction.data().as_slice().to_vec()
    }

    pub fn sys_load_script_hash(&self) -> Byte32 {
        self.script_hash.clone()
    }

    pub fn sys_load_script(&self) -> Vec<u8> {
        let (is_input, index) = self.group_index[0];
        if !self.is_type {
            self.dummy
                .cells
                .get(
                    &self
                        .transaction
                        .inputs()
                        .get(index)
                        .unwrap()
                        .previous_output(),
                )
                .unwrap()
                .0
                .lock()
                .as_slice()
                .to_vec()
        } else {
            let type_sc = if is_input {
                self.dummy
                    .cells
                    .get(
                        &self
                            .transaction
                            .inputs()
                            .get(index)
                            .unwrap()
                            .previous_output(),
                    )
                    .unwrap()
                    .0
                    .type_()
            } else {
                self.transaction.output(index).unwrap().type_()
            };
            type_sc.as_slice().to_vec()
        }
    }

    pub fn sys_load_cell(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.get_input_cell(index);
                if input.is_err() {
                    Result::Err(input.err().unwrap())
                } else {
                    Result::Ok(input.ok().unwrap().0.as_slice().to_vec())
                }
            }
            CkbSysCallSource::Outpout => {
                let cell = self.get_output_cell(index);
                if cell.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(cell.unwrap().as_slice().to_vec())
                }
            }
            CkbSysCallSource::CellDep => {
                let outpoint = self.transaction.cell_deps().get(index);
                if outpoint.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    let (cell, _) = self
                        .dummy
                        .cells
                        .get(&outpoint.unwrap().out_point())
                        .unwrap();
                    Result::Ok(cell.as_slice().to_vec())
                }
            }
            _ => panic!("unsupport"),
        }
    }

    pub fn sys_load_cell_data(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.get_input_cell(index);
                if input.is_err() {
                    Result::Err(input.err().unwrap())
                } else {
                    Result::Ok(input.ok().unwrap().1.to_vec())
                }
            }
            CkbSysCallSource::Outpout => {
                let output = self.transaction.outputs_data().get(index);
                if output.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(output.unwrap().as_slice().split_at(4).1.to_vec())
                }
            }
            CkbSysCallSource::CellDep => {
                let outpoint = self.transaction.cell_deps().get(index);
                if outpoint.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(
                        self.dummy
                            .cells
                            .get(&outpoint.unwrap().out_point())
                            .unwrap()
                            .1
                            .to_vec(),
                    )
                }
            }
            _ => panic!("unsupport"),
        }
    }

    pub fn sys_load_input(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let inputs = self.transaction.inputs();
                let input = inputs.get(index);
                if input.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(input.unwrap().as_slice().to_vec())
                }
            }
            CkbSysCallSource::Outpout => Result::Err(CkbSysCallError::OutOfBound),
            CkbSysCallSource::CellDep => Result::Err(CkbSysCallError::OutOfBound),
            _ => panic!("unsupport"),
        }
    }

    pub fn sys_load_witness(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let witness = self.transaction.witnesses().get(index);
                if witness.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(witness.unwrap().as_slice().split_at(4).1.to_vec())
                }
            }
            CkbSysCallSource::Outpout => {
                let witness = self.transaction.witnesses().get(index);
                if witness.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(witness.unwrap().as_slice().split_at(4).1.to_vec())
                }
            }

            CkbSysCallSource::CellDep => Result::Err(CkbSysCallError::OutOfBound),
            _ => panic!("unsupport"),
        }
    }

    fn load_field_capacity(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.get_input_cell(index);
                if input.is_err() {
                    Result::Err(input.err().unwrap())
                } else {
                    Result::Ok(input.ok().unwrap().0.capacity().raw_data().to_vec())
                }
            }
            CkbSysCallSource::Outpout => {
                let output = self.get_output_cell(index);
                if output.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(output.unwrap().capacity().raw_data().to_vec())
                }
            }
            CkbSysCallSource::GroupInput => {
                if self.is_type {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                if self.group_index.len() <= index {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                let (_, index) = self.group_index[index];
                let cell = self.transaction.inputs().get(index);
                if cell.is_none() {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                let cell = self.dummy.cells.get(&cell.unwrap().previous_output());
                if cell.is_none() {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                Result::Ok(cell.unwrap().0.capacity().raw_data().to_vec())
            }
            CkbSysCallSource::GroupOutpout => {
                if !self.is_type {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                if self.group_index.len() <= index {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                //let (_, index) = self.group_index[index];
                // todo
                Result::Err(CkbSysCallError::InvalidData)
            }
            CkbSysCallSource::CellDep => {
                let cell = self.transaction.cell_deps().get(index);
                if cell.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    let cell = self.dummy.cells.get(&cell.unwrap().out_point());
                    if cell.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(cell.unwrap().0.capacity().raw_data().to_vec())
                    }
                }
            }
        }
    }

    fn load_field_data_hash(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.get_input_cell(index);
                if input.is_err() {
                    Result::Err(input.err().unwrap())
                } else {
                    let data = input.ok().unwrap().1.to_vec();
                    Result::Ok(if data.is_empty() {
                        [0u8; 32].to_vec()
                    } else {
                        blake2b_256(data).to_vec()
                    })
                }
            }
            CkbSysCallSource::Outpout => {
                let output = self.transaction.outputs_data().get(index);
                if output.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    let data = output.unwrap().as_slice().split_at(4).1.to_vec();
                    if data.is_empty() {
                        Result::Ok([0u8; 32].to_vec())
                    } else {
                        Result::Ok(data)
                    }
                }
            }
            CkbSysCallSource::CellDep => {
                let outpoint = self.transaction.cell_deps().get(index);
                if outpoint.is_none() {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                let (_, data) = self
                    .dummy
                    .cells
                    .get(&outpoint.unwrap().out_point())
                    .unwrap();
                Result::Ok(if data.is_empty() {
                    [0u8; 32].to_vec()
                } else {
                    blake2b_256(data.to_vec()).to_vec()
                })
            }
            _ => panic!("unsupport"),
        }
    }

    fn load_field_lock(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.get_input_cell(index);
                if input.is_err() {
                    Result::Err(input.err().unwrap())
                } else {
                    Result::Ok(input.ok().unwrap().0.lock().as_bytes().to_vec())
                }
            }
            CkbSysCallSource::Outpout => {
                let output = self.transaction.outputs().get(index);
                if output.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(output.unwrap().lock().as_bytes().to_vec())
                }
            }
            CkbSysCallSource::CellDep => {
                let outpoint = self.transaction.cell_deps().get(index);
                if outpoint.is_none() {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                let (cell, _) = self
                    .dummy
                    .cells
                    .get(&outpoint.unwrap().out_point())
                    .unwrap();
                Result::Ok(cell.lock().as_bytes().to_vec())
            }
            _ => panic!("unsupport"),
        }
    }

    fn load_field_lock_hash(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.get_input_cell(index);
                if input.is_err() {
                    Result::Err(input.err().unwrap())
                } else {
                    Result::Ok(input.ok().unwrap().0.calc_lock_hash().as_bytes().to_vec())
                }
            }
            CkbSysCallSource::Outpout => {
                let output = self.transaction.outputs().get(index);
                if output.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(output.unwrap().calc_lock_hash().as_bytes().to_vec())
                }
            }
            CkbSysCallSource::CellDep => {
                let outpoint = self.transaction.cell_deps().get(index);
                if outpoint.is_none() {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                let (cell, _) = self
                    .dummy
                    .cells
                    .get(&outpoint.unwrap().out_point())
                    .unwrap();
                Result::Ok(cell.calc_lock_hash().as_bytes().to_vec())
            }
            _ => panic!("unsupport"),
        }
    }

    fn load_field_type(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.get_input_cell(index);
                if input.is_err() {
                    Result::Err(input.err().unwrap())
                } else {
                    let d = input.ok().unwrap().0.type_();
                    if d.is_none() {
                        Result::Err(CkbSysCallError::ItemMissing)
                    } else {
                        Result::Ok(d.as_bytes().to_vec())
                    }
                }
            }
            CkbSysCallSource::Outpout => {
                let output = self.transaction.outputs().get(index);
                if output.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    let d = output.unwrap().type_();
                    if d.is_none() {
                        Result::Err(CkbSysCallError::ItemMissing)
                    } else {
                        Result::Ok(d.as_bytes().to_vec())
                    }
                }
            }
            CkbSysCallSource::CellDep => {
                let outpoint = self.transaction.cell_deps().get(index);
                if outpoint.is_none() {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                let (cell, _) = self
                    .dummy
                    .cells
                    .get(&outpoint.unwrap().out_point())
                    .unwrap();
                let d = cell.type_();
                if d.is_none() {
                    Result::Err(CkbSysCallError::ItemMissing)
                } else {
                    Result::Ok(d.as_bytes().to_vec())
                }
            }
            _ => panic!("unsupport"),
        }
    }

    fn load_field_type_hash(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.get_input_cell(index);
                if input.is_err() {
                    Result::Err(input.err().unwrap())
                } else {
                    let d = input.ok().unwrap().0.type_();
                    if d.is_none() {
                        Result::Err(CkbSysCallError::ItemMissing)
                    } else {
                        let d = Script::from_slice(d.as_slice()).unwrap();
                        Result::Ok(d.calc_script_hash().as_slice().to_vec())
                    }
                }
            }
            CkbSysCallSource::Outpout => {
                let output = self.transaction.outputs().get(index);
                if output.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    let d = output.unwrap().type_();
                    if d.is_none() {
                        Result::Err(CkbSysCallError::ItemMissing)
                    } else {
                        let d = Script::from_slice(d.as_slice()).unwrap();
                        Result::Ok(d.calc_script_hash().as_slice().to_vec())
                    }
                }
            }
            CkbSysCallSource::CellDep => {
                let outpoint = self.transaction.cell_deps().get(index);
                if outpoint.is_none() {
                    return Result::Err(CkbSysCallError::OutOfBound);
                }
                let (cell, _) = self
                    .dummy
                    .cells
                    .get(&outpoint.unwrap().out_point())
                    .unwrap();
                let d = cell.type_();
                if d.is_none() {
                    Result::Err(CkbSysCallError::ItemMissing)
                } else {
                    let d = Script::from_slice(d.as_slice()).unwrap();
                    Result::Ok(d.calc_script_hash().as_slice().to_vec())
                }
            }
            _ => panic!("unsupport"),
        }
    }

    fn load_field_occupied_capacity(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.get_input_cell(index);
                if input.is_err() {
                    Result::Err(input.err().unwrap())
                } else {
                    let (input, data) = input.ok().unwrap();
                    Result::Ok(
                        input
                            .occupied_capacity(Capacity::bytes(data.len()).unwrap())
                            .unwrap()
                            .as_u64()
                            .to_le_bytes()
                            .to_vec(),
                    )
                }
            }
            CkbSysCallSource::Outpout => {
                let output = self.get_output_cell(index);
                let output_data = self.transaction.outputs_data().get(index);
                if output.is_none() || output_data.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(
                        output
                            .unwrap()
                            .occupied_capacity(Capacity::bytes(output_data.unwrap().len()).unwrap())
                            .unwrap()
                            .as_u64()
                            .to_le_bytes()
                            .to_vec(),
                    )
                }
            }
            CkbSysCallSource::CellDep => {
                let cell = self.transaction.cell_deps().get(index);
                if cell.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    let cell = self.dummy.cells.get(&cell.unwrap().out_point());
                    if cell.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        let (cell, cell_data) = cell.unwrap();
                        Result::Ok(
                            cell.occupied_capacity(Capacity::bytes(cell_data.len()).unwrap())
                                .unwrap()
                                .as_u64()
                                .to_le_bytes()
                                .to_vec(),
                        )
                    }
                }
            }
            _ => panic!("unsupport"),
        }
    }

    pub fn sys_load_cell_by_field(
        &self,
        index: usize,
        source: CkbSysCallSource,
        field: CkbSysCallCellField,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match field {
            CkbSysCallCellField::Capacity => self.load_field_capacity(index, source),
            CkbSysCallCellField::DataHash => self.load_field_data_hash(index, source),
            CkbSysCallCellField::Lock => self.load_field_lock(index, source),
            CkbSysCallCellField::LockHash => self.load_field_lock_hash(index, source),
            CkbSysCallCellField::Type => self.load_field_type(index, source),
            CkbSysCallCellField::TypeHash => self.load_field_type_hash(index, source),
            CkbSysCallCellField::OccupiedCapacity => {
                self.load_field_occupied_capacity(index, source)
            }
        }
    }

    fn load_input_field_out_point(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.transaction.inputs().get(index);
                if input.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(input.unwrap().previous_output().as_slice().to_vec())
                }
            }
            CkbSysCallSource::Outpout => Result::Err(CkbSysCallError::OutOfBound),
            CkbSysCallSource::CellDep => Result::Err(CkbSysCallError::OutOfBound),
            _ => panic!("unsupport"),
        }
    }

    fn load_input_field_since(
        &self,
        index: usize,
        source: CkbSysCallSource,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match source {
            CkbSysCallSource::Input => {
                let input = self.transaction.inputs().get(index);
                if input.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(input.unwrap().since().as_slice().to_vec())
                }
            }
            CkbSysCallSource::Outpout => Result::Err(CkbSysCallError::OutOfBound),
            CkbSysCallSource::CellDep => Result::Err(CkbSysCallError::OutOfBound),
            _ => panic!("unsupport"),
        }
    }

    pub fn sys_load_input_by_field(
        &self,
        index: usize,
        source: CkbSysCallSource,
        field: CkbSysCallInputField,
    ) -> Result<Vec<u8>, CkbSysCallError> {
        match field {
            CkbSysCallInputField::OutPoint => self.load_input_field_out_point(index, source),
            CkbSysCallInputField::Since => self.load_input_field_since(index, source),
        }
    }
}

pub fn dbg_print_bytes(d: &Vec<u8>, index: i32, des: &str) {
    if index < 0 {
        println!("{}, len:{} :", des, d.len());
    } else {
        println!("{}, len: {}, index: {} :", des, d.len(), index);
    }

    if d.len() == 0 {
        println!("null\n");
        return;
    }

    let mut count = 0;
    for i in 0..d.len() {
        print!("0x{:0>2X?}, ", d[i]);
        if i % 16 == 15 {
            print!("\n");
        }
        count = i;
    }
    if count % 16 != 15 {
        print!("\n");
    }
    print!("\n");
}
