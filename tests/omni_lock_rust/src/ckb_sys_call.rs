#![allow(unused_imports)]

use ckb_hash::blake2b_256;
use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionView},
    packed::{Byte32, CellOutput, Script},
    prelude::Entity,
};
use std::{cmp::Ordering, option};

use super::dummy_data_loader::DummyDataLoader;

pub struct CkbSysCall {
    pub transaction: TransactionView,
    pub dummy: DummyDataLoader,
    pub script_hash: Byte32,
    pub group_id: usize,

    script_index: usize,
}

#[derive(Copy, Clone)]
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
    pub fn new(transaction: &TransactionView, dummy: &DummyDataLoader) -> Self {
        let (dump_script, _) = dummy
            .cells
            .get(&transaction.inputs().get(0).unwrap().previous_output())
            .unwrap();

        let mut ret = CkbSysCall {
            transaction: transaction.clone(),
            dummy: dummy.clone(),
            script_hash: dump_script.lock().calc_script_hash(),
            group_id: 0,
            script_index: 0xFFFFFFFF,
        };

        let mut index = 0;
        loop {
            let hash = ret.load_script_hash(index).ok().unwrap();
            if ret.script_hash.cmp(&hash) == Ordering::Equal {
                ret.script_index = index;
                break;
            }
            index += 1
        }

        ret
    }

    fn load_script_hash(&self, index: usize) -> Result<Byte32, CkbSysCallError> {
        let input = self.transaction.inputs().get(index);
        if input.is_none() {
            Result::Err(CkbSysCallError::OutOfBound)
        } else {
            let (dump_script, _) = self
                .dummy
                .cells
                .get(&input.unwrap().previous_output())
                .unwrap();
            Result::Ok(dump_script.lock().calc_script_hash())
        }
    }

    fn get_group_index(&self, index: usize) -> Result<usize, CkbSysCallError> {
        let mut group_count = 0;
        let mut i: usize = self.script_index;
        loop {
            if index == group_count {
                return Result::Ok(i);
            }
            i += 1;
            let hash = self.load_script_hash(i);
            if hash.is_err() {
                break;
            }
            if self.script_hash.cmp(&hash.ok().unwrap()) == Ordering::Equal {
                group_count += 1;
            }
        }
        Result::Err(CkbSysCallError::OutOfBound)
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
        let input = self.transaction.inputs().get(self.script_index);
        let (script, _) = self
            .dummy
            .cells
            .get(&input.unwrap().previous_output())
            .unwrap();
        script.lock().as_slice().to_vec()
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
                let output = self.get_output_cell(index);
                if output.is_none() {
                    Result::Err(CkbSysCallError::OutOfBound)
                } else {
                    Result::Ok(output.unwrap().as_slice().to_vec())
                }
            }
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let d = self.get_input_cell(index.ok().unwrap());
                    if d.is_err() {
                        Result::Err(d.err().unwrap())
                    } else {
                        Result::Ok(d.ok().unwrap().0.as_slice().to_vec())
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.get_output_cell(index.ok().unwrap());
                    if output.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(output.unwrap().as_slice().to_vec())
                    }
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let d = self.get_input_cell(index.ok().unwrap());
                    if d.is_err() {
                        Result::Err(d.err().unwrap())
                    } else {
                        Result::Ok(d.ok().unwrap().1.to_vec())
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.transaction.outputs_data().get(index.ok().unwrap());
                    if output.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(output.unwrap().as_slice().split_at(4).1.to_vec())
                    }
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let inputs = self.transaction.inputs();
                    let input = inputs.get(index.ok().unwrap());
                    if input.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(input.unwrap().as_slice().to_vec())
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => Result::Err(CkbSysCallError::OutOfBound),
            CkbSysCallSource::CellDep => Result::Err(CkbSysCallError::OutOfBound),
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let witness = self.transaction.witnesses().get(index.ok().unwrap());
                    if witness.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(witness.unwrap().as_slice().split_at(4).1.to_vec())
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.transaction.outputs_data().get(index.ok().unwrap());
                    if output.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        let witness = self.transaction.witnesses().get(index.ok().unwrap());
                        if witness.is_none() {
                            Result::Err(CkbSysCallError::OutOfBound)
                        } else {
                            Result::Ok(witness.unwrap().as_slice().split_at(4).1.to_vec())
                        }
                    }
                }
            }
            CkbSysCallSource::CellDep => Result::Err(CkbSysCallError::OutOfBound),
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
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let input = self.get_input_cell(index.ok().unwrap());
                    if input.is_err() {
                        Result::Err(input.err().unwrap())
                    } else {
                        Result::Ok(input.ok().unwrap().0.capacity().raw_data().to_vec())
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.get_output_cell(index.ok().unwrap());
                    if output.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(output.unwrap().capacity().raw_data().to_vec())
                    }
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let d = self.get_input_cell(index.ok().unwrap());
                    if d.is_err() {
                        Result::Err(d.err().unwrap())
                    } else {
                        let data = d.ok().unwrap().1.to_vec();
                        Result::Ok(if data.is_empty() {
                            [0u8; 32].to_vec()
                        } else {
                            blake2b_256(data).to_vec()
                        })
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.transaction.outputs_data().get(index.ok().unwrap());
                    if output.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        let data = output.unwrap().as_slice().split_at(4).1.to_vec();
                        Result::Ok(if data.is_empty() {
                            [0u8; 32].to_vec()
                        } else {
                            blake2b_256(data).to_vec()
                        })
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let d = self.get_input_cell(index.ok().unwrap());
                    if d.is_err() {
                        Result::Err(d.err().unwrap())
                    } else {
                        Result::Ok(d.ok().unwrap().0.lock().as_bytes().to_vec())
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.transaction.outputs().get(index.ok().unwrap());
                    if output.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(output.unwrap().lock().as_bytes().to_vec())
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
                Result::Ok(cell.lock().as_bytes().to_vec())
            }
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let d = self.get_input_cell(index.ok().unwrap());
                    if d.is_err() {
                        Result::Err(d.err().unwrap())
                    } else {
                        Result::Ok(d.ok().unwrap().0.calc_lock_hash().as_bytes().to_vec())
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.transaction.outputs().get(index.ok().unwrap());
                    if output.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(output.unwrap().calc_lock_hash().as_bytes().to_vec())
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
                Result::Ok(cell.calc_lock_hash().as_bytes().to_vec())
            }
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let d = self.get_input_cell(index.ok().unwrap());
                    if d.is_err() {
                        Result::Err(d.err().unwrap())
                    } else {
                        let d = d.ok().unwrap().0.type_();
                        if d.is_none() {
                            Result::Err(CkbSysCallError::ItemMissing)
                        } else {
                            Result::Ok(d.as_bytes().to_vec())
                        }
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.transaction.outputs().get(index.ok().unwrap());
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let d = self.get_input_cell(index.ok().unwrap());
                    if d.is_err() {
                        Result::Err(d.err().unwrap())
                    } else {
                        let d = d.ok().unwrap().0.type_();
                        if d.is_none() {
                            Result::Err(CkbSysCallError::ItemMissing)
                        } else {
                            let d = Script::from_slice(d.as_slice()).unwrap();
                            Result::Ok(d.calc_script_hash().as_slice().to_vec())
                        }
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.transaction.outputs().get(index.ok().unwrap());
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let input = self.get_input_cell(index.ok().unwrap());
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
            }
            CkbSysCallSource::GroupOutpout => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let output = self.get_output_cell(index.ok().unwrap());
                    let output_data = self.transaction.outputs_data().get(index.ok().unwrap());
                    if output.is_none() || output_data.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(
                            output
                                .unwrap()
                                .occupied_capacity(
                                    Capacity::bytes(output_data.unwrap().len()).unwrap(),
                                )
                                .unwrap()
                                .as_u64()
                                .to_le_bytes()
                                .to_vec(),
                        )
                    }
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let input = self.transaction.inputs().get(index.ok().unwrap());
                    if input.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(input.unwrap().previous_output().as_slice().to_vec())
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => Result::Err(CkbSysCallError::OutOfBound),
            CkbSysCallSource::CellDep => Result::Err(CkbSysCallError::OutOfBound),
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
            CkbSysCallSource::GroupInput => {
                let index = self.get_group_index(index);
                if index.is_err() {
                    Result::Err(index.err().unwrap())
                } else {
                    let input = self.transaction.inputs().get(index.ok().unwrap());
                    if input.is_none() {
                        Result::Err(CkbSysCallError::OutOfBound)
                    } else {
                        Result::Ok(input.unwrap().since().as_slice().to_vec())
                    }
                }
            }
            CkbSysCallSource::GroupOutpout => Result::Err(CkbSysCallError::OutOfBound),
            CkbSysCallSource::CellDep => Result::Err(CkbSysCallError::OutOfBound),
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

pub fn sys_call_dump_all(ckb_sys_call: CkbSysCall) {
    fn dbg_print_byte32(d: &Byte32, des: &str) {
        dbg_print_bytes(&d.raw_data().to_vec(), -1, des);
    }

    fn dbg_print_bytes_hash(d: &Vec<u8>, index: i32, des: &str) {
        if index < 0 {
            println!("{}, len:{} :", des, d.len());
        } else {
            println!("{}, len: {}, index: {} :", des, d.len(), index);
        }

        if d.len() == 0 {
            println!("null\n");
            return;
        }

        let hash = ckb_hash::blake2b_256(d);
        for i in 0..32 {
            print!("{:0>2X?}", hash[i]);
        }
        print!("\n\n");
    }

    fn dump_cell(ckb_sys_call: &CkbSysCall) {
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell(index, CkbSysCallSource::Input);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell(index, CkbSysCallSource::Outpout);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "output");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell(index, CkbSysCallSource::GroupInput);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "group input");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell(index, CkbSysCallSource::GroupOutpout);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "group output");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell(index, CkbSysCallSource::CellDep);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "dep");
        }
    }

    fn dump_cell_data(ckb_sys_call: &CkbSysCall) {
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell_data(index, CkbSysCallSource::Input);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell_data(index, CkbSysCallSource::Outpout);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "output data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell_data(index, CkbSysCallSource::GroupInput);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "group input data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell_data(index, CkbSysCallSource::GroupOutpout);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "group output data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell_data(index, CkbSysCallSource::CellDep);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "dep data");
        }
    }

    fn dump_input(ckb_sys_call: &CkbSysCall) {
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_input(index, CkbSysCallSource::Input);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input input data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_input(index, CkbSysCallSource::Outpout);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input output data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_input(index, CkbSysCallSource::GroupInput);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input group input data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_input(index, CkbSysCallSource::GroupOutpout);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input group output data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_input(index, CkbSysCallSource::CellDep);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input dep data");
        }
    }

    fn dump_witness(ckb_sys_call: &CkbSysCall) {
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_witness(index, CkbSysCallSource::Input);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "witness input data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_witness(index, CkbSysCallSource::Outpout);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "witness output data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_witness(index, CkbSysCallSource::GroupInput);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "witness group input data");
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_witness(index, CkbSysCallSource::GroupOutpout);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(
                &ret.ok().unwrap(),
                index as i32,
                "witness group output data",
            );
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_witness(index, CkbSysCallSource::CellDep);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                }
            }
            dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "witness dep data");
        }
    }

    fn dump_cell_field(ckb_sys_call: &CkbSysCall, field: CkbSysCallCellField, out_hash: bool) {
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell_by_field(index, CkbSysCallSource::Input, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "field input data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "field input data");
            } else {
                dbg_print_bytes(&ret.ok().unwrap(), index as i32, "field input data");
            }
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell_by_field(index, CkbSysCallSource::Outpout, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "field output data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "field output data");
            } else {
                dbg_print_bytes(&ret.ok().unwrap(), index as i32, "field output data");
            }
        }
        for index in 0usize..64usize {
            let ret =
                ckb_sys_call.sys_load_cell_by_field(index, CkbSysCallSource::GroupInput, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "field group input data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "field group input data");
            } else {
                dbg_print_bytes(&ret.ok().unwrap(), index as i32, "field group input data");
            }
        }
        for index in 0usize..64usize {
            let ret =
                ckb_sys_call.sys_load_cell_by_field(index, CkbSysCallSource::GroupOutpout, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "field group output data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "field group output data");
            } else {
                dbg_print_bytes(&ret.ok().unwrap(), index as i32, "field group output data");
            }
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_cell_by_field(index, CkbSysCallSource::CellDep, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "field dep data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "field dep data");
            } else {
                dbg_print_bytes(&ret.ok().unwrap(), index as i32, "field dep data");
            }
        }
    }

    fn dump_input_field(ckb_sys_call: &CkbSysCall, field: CkbSysCallInputField, out_hash: bool) {
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_input_by_field(index, CkbSysCallSource::Input, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "input field input data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input field input data");
            } else {
                dbg_print_bytes(&ret.ok().unwrap(), index as i32, "input field input data");
            }
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_input_by_field(index, CkbSysCallSource::Outpout, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "input field output data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input field output data");
            } else {
                dbg_print_bytes(&ret.ok().unwrap(), index as i32, "input field output data");
            }
        }
        for index in 0usize..64usize {
            let ret =
                ckb_sys_call.sys_load_input_by_field(index, CkbSysCallSource::GroupInput, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "input field group input data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(
                    &ret.ok().unwrap(),
                    index as i32,
                    "input field group input data",
                );
            } else {
                dbg_print_bytes(
                    &ret.ok().unwrap(),
                    index as i32,
                    "input field group input data",
                );
            }
        }
        for index in 0usize..64usize {
            let ret =
                ckb_sys_call.sys_load_input_by_field(index, CkbSysCallSource::GroupOutpout, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "input field group output data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(
                    &ret.ok().unwrap(),
                    index as i32,
                    "input field group output data",
                );
            } else {
                dbg_print_bytes(
                    &ret.ok().unwrap(),
                    index as i32,
                    "input field group output data",
                );
            }
        }
        for index in 0usize..64usize {
            let ret = ckb_sys_call.sys_load_input_by_field(index, CkbSysCallSource::CellDep, field);
            if ret.is_err() {
                let err = ret.clone().err().unwrap();
                if err == CkbSysCallError::OutOfBound {
                    break;
                } else if err != CkbSysCallError::Success {
                    println!(
                        "input field dep data failed, ret: {}, index: {}",
                        err as u32, index
                    );
                    break;
                }
            }
            if out_hash {
                dbg_print_bytes_hash(&ret.ok().unwrap(), index as i32, "input field dep data");
            } else {
                dbg_print_bytes(&ret.ok().unwrap(), index as i32, "input field dep data");
            }
        }
    }

    let tx_hash = ckb_sys_call.sys_load_tx_hash();
    dbg_print_byte32(&tx_hash, "tx hash");

    let tx_data = ckb_sys_call.sys_load_transaction();
    dbg_print_bytes_hash(&tx_data, -1, "tx data");

    let script_hash = ckb_sys_call.sys_load_script_hash();
    dbg_print_byte32(&script_hash, "script hash");

    let script_data = ckb_sys_call.sys_load_script();
    dbg_print_bytes_hash(&script_data, -1, "script data");

    dump_cell(&ckb_sys_call);
    dump_cell_data(&ckb_sys_call);
    dump_input(&ckb_sys_call);
    dump_witness(&ckb_sys_call);

    println!("cell by field : FIELD_CAPACITY");
    dump_cell_field(&ckb_sys_call, CkbSysCallCellField::Capacity, false);
    println!("cell by field : FIELD_DATA_HASH");
    dump_cell_field(&ckb_sys_call, CkbSysCallCellField::DataHash, false);
    println!("cell by field : FIELD_LOCK");
    dump_cell_field(&ckb_sys_call, CkbSysCallCellField::Lock, true);
    println!("cell by field : FIELD_LOCK_HASH");
    dump_cell_field(&ckb_sys_call, CkbSysCallCellField::LockHash, false);
    println!("cell by field : FIELD_TYPE");
    dump_cell_field(&ckb_sys_call, CkbSysCallCellField::Type, true);
    println!("cell by field : FIELD_TYPE_HASH");
    dump_cell_field(&ckb_sys_call, CkbSysCallCellField::TypeHash, false);
    println!("cell by field : FIELD_OCC_CAP");
    dump_cell_field(&ckb_sys_call, CkbSysCallCellField::OccupiedCapacity, false);

    println!("input by field : INPUT_FIELD_OUTPOINT");
    dump_input_field(&ckb_sys_call, CkbSysCallInputField::OutPoint, false);
    println!("input by field : INPUT_FIELD_SINCE");
    dump_input_field(&ckb_sys_call, CkbSysCallInputField::Since, false);
}
