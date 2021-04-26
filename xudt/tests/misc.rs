use ckb_types::packed::Byte32;
use ckb_types::prelude::Entity;

pub const MAX_CYCLES: u64 = std::u64::MAX;

pub fn debug_printer(script: &Byte32, msg: &str) {
    let slice = script.as_slice();
    let str = format!(
        "Script({:x}{:x}{:x}{:x}{:x})",
        slice[0], slice[1], slice[2], slice[3], slice[4]
    );
    println!("{:?}: {}", str, msg);
}
