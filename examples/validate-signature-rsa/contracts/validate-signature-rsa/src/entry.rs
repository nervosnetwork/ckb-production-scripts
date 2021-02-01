// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::ckb_types::prelude::*;
use ckb_std::debug;
use ckb_std::ckb_types::bytes::Bytes;
use ckb_std::high_level::*;
use ckb_std::ckb_constants::*;
use ckb_std::error::SysError;
use ckb_std::dynamic_loading;
use blake2b_ref::{Blake2b, Blake2bBuilder};
use alloc::vec::Vec;

use crate::{code_hashes, error::Error};

const BLAKE2B_BLOCK_SIZE : usize = 32;
const BLAKE2B160_BLOCK_SIZE : usize = 20;

fn new_blake2b() -> Blake2b {
    const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}

fn get_key_size(key_size_enum: u8) -> usize {
    let key_size = match key_size_enum {
        1 => 1024,
        2 => 2048,
        3 => 4096,
        _ => 0,
    };
    if key_size == 0 {
        panic!("wrong key size");
    };
    key_size
}

fn calculate_pub_key_hash(signature: &Bytes, key_size: usize) -> Vec<u8> {
    let mut hash: Vec<u8> = Default::default();
    hash.resize(BLAKE2B_BLOCK_SIZE, 0);

    let mut blake2b = new_blake2b();
    blake2b.update(&signature.slice(4..8));
    blake2b.update(&signature.slice(8..(8+key_size/8)));
    blake2b.finalize(hash.as_mut_slice());
    hash.truncate(BLAKE2B160_BLOCK_SIZE);
    hash
}


fn calculate_rsa_info_length(key_size_enum: u8) -> usize {
    8 + get_key_size(key_size_enum) / 4
}

type DlContextType = dynamic_loading::CKBDLContext<[u8; 80*1024]>;
/*
int validate_signature(void *prefilled_data, const uint8_t *signature_buffer,
                       size_t signature_size, const uint8_t *msg_buf,
                       size_t msg_size, uint8_t *output, size_t *output_len);
*/
type DlFnType = unsafe extern "C" fn(fill: *const u8, signature: *const u8,
                signature_size: usize, msg_buf: *const u8, msg_size: usize, 
                output: *const u8, output_len: *const usize) -> isize;

pub fn main() -> Result<(), Error> {
    let validate_signature_fn : dynamic_loading::Symbol<DlFnType>;
    unsafe {
        let mut ctx = DlContextType::new();
        let lib = ctx
                .load(&code_hashes::CODE_HASH_SHARED_LIB)
                .expect("load shared lib");
        validate_signature_fn = lib.get(b"validate_signature", ).expect("get function symbol validate_signature from dyanmic library");
    }

    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    // debug!("script args is {:?}", args);

    // return an error if args is invalid
    if args.is_empty() {
        debug!("args is empty");
        return Err(Error::InvalidArgs0);
    }

    let tx_hash = load_tx_hash()?;
    // debug!("tx hash is {:?}", tx_hash);

    let signature: Bytes = load_witness_args(0, Source::GroupInput)?.lock()
            .to_opt()
            .ok_or(Error::InvalidArgs1)?
            .unpack();
    let signature_len = signature.len();

    //   typedef struct RsaInfo {
    //   uint8_t algorithm_id;
    //   uint8_t key_size;
    //   uint8_t padding;
    //   uint8_t md_type;
    //   uint32_t E;
    //   uint8_t N[PLACEHOLDER_SIZE];
    //   uint8_t sig[PLACEHOLDER_SIZE];
    // } RsaInfo;
    let algorithm_id = signature[0];
    assert_eq!(algorithm_id, 1);

    let key_size_enum = signature[1];
    let padding = signature[2];
    assert!(padding == 0 || padding == 1);
    let md_type = signature[3];
    assert!(md_type > 0);
    
    let key_size = get_key_size(key_size_enum);
    assert!(key_size % 1024 == 0);

    let info_len = calculate_rsa_info_length(key_size_enum);
    if signature.len() != info_len {
        return Err(Error::InvalidArgs1);
    }
    let mut blake2b = new_blake2b();
    // hash, step 1
    blake2b.update(&tx_hash);
    // hash, step 2
    blake2b.update(&signature_len.to_le_bytes());
    let mut index = 1;
    loop {
        let result = load_witness_args(index, Source::Input);
        match result {
            Ok(args) => {
                let buff : Bytes = args.lock().to_opt().ok_or(Error::InvalidArgs1)?.unpack();
                let buff_size = buff.len();
                // hash, step 3
                blake2b.update(&buff_size.to_le_bytes());
                blake2b.update(&buff);
            },
            Err(err) if err == SysError::IndexOutOfBound => break,
            Err(_) => {
                debug!("load_witness_args() failed");
                return Err(Error::SyscallError);
            }
        }
        index += 1;
    }
    let mut message = [0 as u8; BLAKE2B_BLOCK_SIZE];
    blake2b.finalize(&mut message);

    // dummpy, not used
    let dummy_len : usize = 4;
    let dummy_output = [0 as u8; 4];
    let dummy = [0 as u8; 4];

    unsafe {
        let rsa_info  = signature.as_ptr();
        let ret = validate_signature_fn(&dummy as *const u8, rsa_info, signature_len, &message as *const u8, BLAKE2B_BLOCK_SIZE, 
                        &dummy_output as *const u8, &dummy_len as *const usize);
        if ret != 0 {
            debug!("validate_signature() failed: {}", ret);
            return Err(Error::ValidateSignatureError)
        }
    }
    let pub_key_hash = calculate_pub_key_hash(&signature, key_size);
    let args_hash : Vec<u8> = args.into();
    if pub_key_hash.len() != args_hash.len() {
        debug!("pub_key_hash.len() != args_hash.len() ");
        return Err(Error::ArgsMismatched);
    } else {
        let len = pub_key_hash.len();
        for i in 0..len {
            if pub_key_hash[i] != args_hash[i] {
                debug!("pub_key_hash != args_hash ");
                return Err(Error::ArgsMismatched);
            }
        }
    }
    return Ok(())
}

