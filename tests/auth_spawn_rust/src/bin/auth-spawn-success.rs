use auth_spawn_rust::generate_sighash_all;
use auth_spawn_rust::read_tx_template;
use ckb_crypto::secp::Privkey;
use ckb_jsonrpc_types::JsonBytes;
use ckb_mock_tx_types::ReprMockTransaction;
use ckb_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{CellOutput, WitnessArgsBuilder},
    prelude::*,
    H256,
};
use lazy_static::lazy_static;

static G_PRIVKEY_BUF: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

enum AuthEntryCategoryType {
    // Exec = 0,
    // DL = 1,
    Spawn = 2,
}

lazy_static! {
    pub static ref AUTH_DL: Bytes = Bytes::from(&include_bytes!("../../../../build/auth")[..]);
    pub static ref AUTH_DL_HASH_TYPE: ScriptHashType = ScriptHashType::Data1;
}

fn update_auth_code_hash(tx: &mut ReprMockTransaction) {
    let hash = CellOutput::calc_data_hash(&AUTH_DL).as_slice().to_vec();
    for input in tx.mock_info.inputs.as_mut_slice() {
        let mut buf = input.output.lock.args.as_bytes().to_vec();
        buf.extend_from_slice(&hash);

        buf.extend_from_slice(&[
            AUTH_DL_HASH_TYPE.clone().into(),
            AuthEntryCategoryType::Spawn as u8,
        ]);

        input.output.lock.args = JsonBytes::from_vec(buf);
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = Privkey::from(H256::from(G_PRIVKEY_BUF));

    let mut tx = read_tx_template("templates/auth-spawn-success.json")?;
    update_auth_code_hash(&mut tx);

    let message = generate_sighash_all(&tx, 0)?;

    let sig = private_key
        .sign_recoverable(&H256::from(message))
        .expect("sign")
        .serialize();

    tx.tx.witnesses.clear();
    tx.tx.witnesses.push(JsonBytes::from_bytes(
        WitnessArgsBuilder::default()
            .lock(Some(Bytes::from(sig)).pack())
            .build()
            .as_bytes(),
    ));

    let json = serde_json::to_string_pretty(&tx).unwrap();
    println!("{}", json);
    Ok(())
}
