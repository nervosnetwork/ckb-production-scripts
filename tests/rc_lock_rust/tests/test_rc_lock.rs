#![allow(unused_imports)]
#![allow(dead_code)]

mod misc;

use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{bytes::Bytes, bytes::BytesMut, packed::WitnessArgs, prelude::*, H256};
use lazy_static::lazy_static;
use misc::{
    blake160, build_resolved_tx, debug_printer, gen_tx, gen_tx_with_grouped_args, gen_witness_lock,
    sign_tx, sign_tx_by_input_group, sign_tx_hash, DummyDataLoader, TestConfig, TestScheme,
    ERROR_ENCODING, ERROR_PUBKEY_BLAKE160_HASH, ERROR_WITNESS_SIZE, IDENTITY_FLAGS_PUBKEY_HASH,
    MAX_CYCLES,
};

#[test]
fn test_owner_lock() {}
