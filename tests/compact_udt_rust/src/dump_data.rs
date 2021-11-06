use crate::dummy_data_loader::DummyDataLoader;
use ckb_types::{
    core::TransactionView,
    packed::{Byte32},
    prelude::Entity,
};
use lazy_static::lazy_static;

lazy_static! {
    static ref DUMP_VAL_HEADER: String = String::from("dump_data_");
}

fn print_mem(d: &[u8]) {
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

pub fn dbg_print_mem(d: &[u8], n: &str) {
    println!("{}, size:{}", n, d.len());
    print_mem(d);
}

pub fn dbg_print_mem_code(d: &[u8], n: &str) {
    println!("uint8_t {}[] = {{", n);
    for i in 0..d.len() {
        print!("{:#04X}, ", d[i]);
        if i % 16 == 15 {
            print!("\n");
        }
    }
    print!("}}\n");
}

pub fn dbg_print_hash(d: &[u8], n: &str) {
    let mut b2 = ckb_hash::new_blake2b();
    b2.update(d);
    let mut h = [0; 32];
    b2.finalize(&mut h);

    println!("{}, size is:{}, hash is:", n, d.len());
    for i in 0..(32 / 4) {
        print!(
            "{:02X}{:02X}{:02X}{:02X}-",
            h[i],
            h[i + 1],
            h[i + 2],
            h[i + 3]
        );
    }
    print!("\n");
}

fn print_c_uint8_buf(val_name: &str, d: &[u8]) {
    println!("std::vector<uint8_t> {}{} = {{", DUMP_VAL_HEADER.as_str(), val_name);
    print_mem(d);
    println!("}};\n");
}

fn print_c_uint8_buf_num(val_name: &str, num: usize, d: &[u8]) {
    println!("uint8_t {}{}_{:02}[] = {{", DUMP_VAL_HEADER.as_str(), val_name, num);
    print_mem(d);
    println!("}};");
}

fn print_c_begin() {
    print!("\n\n");
    println!("#ifndef _RUST_OUTPUT_TEST_DATA_H_");
    println!("#define _RUST_OUTPUT_TEST_DATA_H_");
    println!();
    println!("#include <stddef.h>");
    println!("#include <stdint.h>");
    println!("#include <vector>");
    print!("\n\n");
}

fn print_c_end() {
    print!("\n\n");
    println!("#endif // _RUST_OUTPUT_TEST_DATA_H_");
    print!("\n\n");
}

struct CellInfo {
    pub index: usize,
    pub input_lock_hash: Byte32,

    pub input_cell_data: Vec<u8>,
    pub input_scritp_data: Vec<u8>,

    pub output_cell_data: Vec<u8>,
    pub output_scritp_data: Vec<u8>,

    pub witness: Vec<u8>,
}

impl CellInfo {
    pub fn new() -> Self {
        Self {
            index: 0xFFFFFFFF,
            input_lock_hash: Byte32::new([0; 32]),
            input_cell_data: Vec::new(),
            input_scritp_data: Vec::new(),

            output_cell_data: Vec::new(),
            output_scritp_data: Vec::new(),

            witness: Vec::new(),
        }
    }
}

fn print_cells_info(cells_info: Vec<CellInfo>) {
    println!("std::vector<std::vector<uint8_t>> {}input_lock_hash = {{", DUMP_VAL_HEADER.as_str());
    for cell in &cells_info {
        println!("{{");
        print_mem(cell.input_lock_hash.as_slice());
        println!("}},\n");
    }
    println!("}};\n");

    println!("std::vector<std::vector<uint8_t>> {}input_cell_data = {{", DUMP_VAL_HEADER.as_str());
    for cell in &cells_info {
        println!("{{");
        print_mem(cell.input_cell_data.as_slice());
        println!("}},\n");
    }
    println!("}};\n");

    println!("std::vector<std::vector<uint8_t>> {}input_scritp_data = {{", DUMP_VAL_HEADER.as_str());
    for cell in &cells_info {
        println!("{{");
        print_mem(cell.input_scritp_data.as_slice());
        println!("}},\n");
    }
    println!("}};\n");

    println!("std::vector<std::vector<uint8_t>> {}output_cell_data = {{", DUMP_VAL_HEADER.as_str());
    for cell in &cells_info {
        println!("{{");
        print_mem(cell.output_cell_data.as_slice());
        println!("}},\n");
    }
    println!("}};\n");


    println!("std::vector<std::vector<uint8_t>> {}output_scritp_data = {{", DUMP_VAL_HEADER.as_str());
    for cell in &cells_info {
        println!("{{");
        print_mem(cell.output_scritp_data.as_slice());
        println!("}},\n");
    }
    println!("}};\n");

    println!("std::vector<std::vector<uint8_t>> {}witness = {{", DUMP_VAL_HEADER.as_str());
    for cell in &cells_info {
        println!("{{");
        print_mem(cell.witness.as_slice());
        println!("}},\n");
    }
    println!("}};\n");
}

pub fn dump_data(tx: TransactionView, data_loader: DummyDataLoader, cudt_hash:Byte32) {
    print_c_begin();

    let hash = tx.hash();
    print_c_uint8_buf("tx_hash", hash.as_slice());

    print_c_uint8_buf("cudt_lock_hash", cudt_hash.as_slice());

    let mut cells_info: Vec<CellInfo> = Vec::new();
    for i in 0..tx.inputs().len() {
        let mut cellinfo = CellInfo::new();
        cellinfo.index = i;
        let outpoint = tx.inputs().get(i).unwrap().previous_output();
        let input = data_loader.cells.get(&outpoint);
        let (input, cell_data) = input.unwrap();
        let lock_script = input.lock();

        cellinfo.input_cell_data = cell_data.to_vec();
        cellinfo.input_lock_hash = lock_script.code_hash();
        cellinfo.input_scritp_data = input.lock().as_bytes().to_vec();
        
        let output = tx.output(i).unwrap();
        cellinfo.output_cell_data = tx.outputs_data().get(i).unwrap().as_slice().to_vec();
        cellinfo.output_cell_data = cellinfo.output_cell_data.split_at(4).1.to_vec();
        cellinfo.output_scritp_data = output.lock().as_bytes().to_vec();

        cellinfo.witness = tx.witnesses().get(i).unwrap().as_bytes().to_vec();
        cellinfo.witness = cellinfo.witness.split_at(4).1.to_vec();

        cells_info.push(cellinfo);
    }

    print_cells_info(cells_info);

    print_c_end();
}
