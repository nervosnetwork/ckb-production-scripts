use crate::{dummy_data_loader::DummyDataLoader, TXScriptCode};
use ckb_types::{
    core::TransactionView,
    packed::{Byte32, CellOutput},
    prelude::Entity,
};
use json::{self, JsonValue};
use lazy_static::lazy_static;
use std::fs::File;

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
    println!(
        "std::vector<uint8_t> {}{} = {{",
        DUMP_VAL_HEADER.as_str(),
        val_name
    );
    print_mem(d);
    println!("}};\n");
}

fn print_c_uint8_buf_num(val_name: &str, num: usize, d: &[u8]) {
    println!(
        "uint8_t {}{}_{:02}[] = {{",
        DUMP_VAL_HEADER.as_str(),
        val_name,
        num
    );
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

fn bytes_to_str(d: &[u8]) -> String {
    let mut s: String = String::new();
    for i in 0..d.len() {
        s.push_str(&String::from(format!("{:02X}-",d[i])));
    }
    s
}

fn byte32_to_str(d: &Byte32) -> String {
    bytes_to_str(d.as_slice())
}

struct CellInfo {
    index: usize,
    input_lock_hash: Byte32,
    input_lock_code_hash: Byte32,

    input_cell_data: Vec<u8>,
    input_scritp_data: Vec<u8>,

    output_cell_data: Vec<u8>,
    output_scritp_data: Vec<u8>,

    witness: Vec<u8>,
}

impl CellInfo {
    pub fn new() -> Self {
        Self {
            index: 0xFFFFFFFF,
            input_lock_hash: Byte32::new([0; 32]),
            input_lock_code_hash: Byte32::new([0; 32]),
            input_cell_data: Vec::new(),
            input_scritp_data: Vec::new(),

            output_cell_data: Vec::new(),
            output_scritp_data: Vec::new(),

            witness: Vec::new(),
        }
    }
}

struct DepsInfo {
    index: usize,
    data_hash: Byte32,
}
pub struct DumpData {
    name: String,
    tx_hash: Byte32,
    cudt_lock_hash: Byte32,
    cells: Vec<CellInfo>,
    deps: Vec<DepsInfo>,
    deps_info: Vec<TXScriptCode>,
}

impl DumpData {
    pub fn output_ctrl(&self) {
        print_c_begin();

        print_c_uint8_buf("tx_hash", self.tx_hash.as_slice());
        print_c_uint8_buf("cudt_lock_hash", self.cudt_lock_hash.as_slice());
        self.print_cells_info();

        print_c_end();
    }

    pub fn output_json(&self) {
        let mut root = JsonValue::new_object();
        let xx = byte32_to_str(&self.tx_hash);

        root["tx_hash"] = xx.into();
        root["cudt_hash"] = byte32_to_str(&self.cudt_lock_hash).into();

        let mut cells = JsonValue::new_array();
        for cell in &self.cells {
            let mut json_cell = JsonValue::new_object();
            json_cell["index"] = cell.index.into();
            json_cell["lock_hash"] = byte32_to_str(&cell.input_lock_hash).into();
            json_cell["lock_code_hash"] = byte32_to_str(&cell.input_lock_code_hash).into();

            json_cell["inptu_cell_data"] = bytes_to_str(cell.input_cell_data.as_slice()).into();
            json_cell["inptu_script_data"] = bytes_to_str(cell.input_scritp_data.as_slice()).into();

            json_cell["outptu_cell_data"] = bytes_to_str(cell.output_cell_data.as_slice()).into();
            json_cell["outptu_script_data"] = bytes_to_str(cell.output_scritp_data.as_slice()).into();

            json_cell["witness"] = bytes_to_str(cell.witness.as_slice()).into();

            let err = cells.push(json_cell);

            assert!(
                err.is_ok(),
                "push tx data error: {}",
                err.unwrap_err().to_string()
            );
        }
        root["cells"] = cells;

        let mut deps = JsonValue::new_array();
        for d in &self.deps {
            let mut json_deps = JsonValue::new_object();
            json_deps["index"] = d.index.into();
            json_deps["data_hash"] = byte32_to_str(&d.data_hash).into();

            let path: String = self.get_cell_path(&d.data_hash).into();
            let mut config_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            config_path.push("src");
            config_path.push(path.clone().as_str());
            let path = config_path.as_path().to_str().unwrap().into();
            json_deps["data_path"] = path;

            let err = deps.push(json_deps);
            assert!(
                err.is_ok(),
                "push deps error: {}",
                err.unwrap_err().to_string()
            );
        }
        root["deps"] = deps;

        let path = String::from("test_data/") + self.name.as_str() + ".json";
        let mut fs = File::create(path).expect("create file failed");
        root.write(&mut fs).expect("write json failed");

        // let val =  json::JsonValue::new_object()
        // root.push(value)
    }

    fn print_cells_info(&self) {
        println!(
            "std::vector<std::vector<uint8_t>> {}input_lock_hash = {{",
            DUMP_VAL_HEADER.as_str()
        );
        for cell in &self.cells {
            println!("{{");
            print_mem(cell.input_lock_hash.as_slice());
            println!("}},\n");
        }
        println!("}};\n");

        println!(
            "std::vector<std::vector<uint8_t>> {}input_cell_data = {{",
            DUMP_VAL_HEADER.as_str()
        );
        for cell in &self.cells {
            println!("{{");
            print_mem(cell.input_cell_data.as_slice());
            println!("}},\n");
        }
        println!("}};\n");

        println!(
            "std::vector<std::vector<uint8_t>> {}input_scritp_data = {{",
            DUMP_VAL_HEADER.as_str()
        );
        for cell in &self.cells {
            println!("{{");
            print_mem(cell.input_scritp_data.as_slice());
            println!("}},\n");
        }
        println!("}};\n");

        println!(
            "std::vector<std::vector<uint8_t>> {}output_cell_data = {{",
            DUMP_VAL_HEADER.as_str()
        );
        for cell in &self.cells {
            println!("{{");
            print_mem(cell.output_cell_data.as_slice());
            println!("}},\n");
        }
        println!("}};\n");

        println!(
            "std::vector<std::vector<uint8_t>> {}output_scritp_data = {{",
            DUMP_VAL_HEADER.as_str()
        );
        for cell in &self.cells {
            println!("{{");
            print_mem(cell.output_scritp_data.as_slice());
            println!("}},\n");
        }
        println!("}};\n");

        println!(
            "std::vector<std::vector<uint8_t>> {}witness = {{",
            DUMP_VAL_HEADER.as_str()
        );
        for cell in &self.cells {
            println!("{{");
            print_mem(cell.witness.as_slice());
            println!("}},\n");
        }
        println!("}};\n");
    }

    fn get_cell_path(&self, hash: &Byte32) -> String {
        for d in &self.deps_info {
            if d.code_hash == *hash {
                return d.path.clone();
            }
        }
        String::new()
    }
}

pub fn dump_data(
    tx: TransactionView,
    mod_name: String,
    data_loader: DummyDataLoader,
    cudt_hash: Byte32,
    cell_deps_info: Vec<TXScriptCode>,
) -> DumpData {
    let tx_hash = tx.hash();
    let cudt_lock_hash = cudt_hash;
    let mut cells_info: Vec<CellInfo> = Vec::new();
    for i in 0..tx.inputs().len() {
        let mut cellinfo = CellInfo::new();
        cellinfo.index = i;
        let outpoint = tx.inputs().get(i).unwrap().previous_output();
        let input = data_loader.cells.get(&outpoint);
        let (input, cell_data) = input.unwrap();
        let lock_script = input.lock();

        cellinfo.input_cell_data = cell_data.to_vec();
        cellinfo.input_lock_hash = lock_script.calc_script_hash();
        cellinfo.input_lock_code_hash = lock_script.code_hash();
        cellinfo.input_scritp_data = input.lock().as_bytes().to_vec();

        let output = tx.output(i).unwrap();
        cellinfo.output_cell_data = tx.outputs_data().get(i).unwrap().as_slice().to_vec();
        cellinfo.output_cell_data = cellinfo.output_cell_data.split_at(4).1.to_vec();
        cellinfo.output_scritp_data = output.lock().as_bytes().to_vec();

        cellinfo.witness = tx.witnesses().get(i).unwrap().as_bytes().to_vec();
        cellinfo.witness = cellinfo.witness.split_at(4).1.to_vec();

        cells_info.push(cellinfo);
    }

    let mut deps_info: Vec<DepsInfo> = Vec::new();
    for i in 0..tx.cell_deps().len() {
        let outpoint = tx.cell_deps().get(i).unwrap().out_point();
        let (_dep, dep_data) = data_loader.cells.get(&outpoint).unwrap();

        deps_info.push(DepsInfo {
            index: i,
            data_hash: CellOutput::calc_data_hash(&dep_data),
        });
    }

    DumpData {
        name: mod_name,
        tx_hash,
        cudt_lock_hash,
        cells: cells_info,
        deps: deps_info,
        deps_info: cell_deps_info,
    }
}
