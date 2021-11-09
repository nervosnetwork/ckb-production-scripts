use ckb_types::bytes::Bytes;
use lazy_static::lazy_static;

use compact_udt_rust::{CellID, TXBuilder, TXTransfer, TXUser, UserID, WitnessTransferTargetType};

lazy_static! {
    pub static ref COMPACT_UDT_LOCK_SCRIPT_BIN: Bytes =
        Bytes::from(include_bytes!("../../../build/compact_udt_lock").as_ref());
    pub static ref SIMPLE_UDT_TYPE_SCRIPT_BIN: Bytes =
        Bytes::from(include_bytes!("../../../build/simple_udt").as_ref());
    pub static ref ALWAYS_SUCCESS_SCRIPT_BIN: Bytes =
        Bytes::from(include_bytes!("../../../build/always_success").as_ref());
    pub static ref XUDT_SCRIPT_BIN: Bytes =
        Bytes::from(include_bytes!("../../../build/always_success").as_ref());
    pub static ref AUTH_SCRIPT_DL: Bytes =
        Bytes::from(include_bytes!("../../../build/auth").as_ref());
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(include_bytes!("../../../build/secp256k1_data").as_ref());
}

pub struct MiscUserData {
    pub id: u32,
    pub n: u32,
    pub a: u128,
}

pub struct MiscCellData {
    pub lock_scritp: u32,
    pub type_scritp: u32,

    pub i_amount: u128,
    pub o_amount: u128,
    pub users: Vec<MiscUserData>,
}

pub struct MiscTransferData {
    pub sc: u32,   // source cell id
    pub sd: u32,   // source identity
    pub tc: u32,   // target cell id
    pub td: u32,   // target identity
    pub tt: u32,   // target type: 0: None, 1: ScritpHash, 2: Identity, 3: Between
    pub a: u128,   // amount
    pub fee: u128, // fee
}

pub fn gen_tx_builder(
    builder: TXBuilder,
    cells: Vec<MiscCellData>,
    transfers: Vec<MiscTransferData>,
) -> TXBuilder {
    let mut builder = builder;
    let mut scritp_code_id_vec = Vec::new();
    let (builder_tmp, sc_id) = builder.add_script_code(COMPACT_UDT_LOCK_SCRIPT_BIN.clone());
    builder = builder_tmp.set_script_cudt_id(sc_id);
    scritp_code_id_vec.push(sc_id);

    let (builder_tmp, sc_id) = builder.add_script_code(SIMPLE_UDT_TYPE_SCRIPT_BIN.clone());
    builder = builder_tmp.set_scritp_sudt_id(sc_id);
    scritp_code_id_vec.push(sc_id);

    let (builder_tmp, sc_id) = builder.add_script_code(ALWAYS_SUCCESS_SCRIPT_BIN.clone());
    builder = builder_tmp;
    scritp_code_id_vec.push(sc_id);

    let (builder_tmp, sc_id) = builder.add_script_code(XUDT_SCRIPT_BIN.clone());
    builder = builder_tmp.set_scritp_xudt_id(sc_id);
    scritp_code_id_vec.push(sc_id);

    let (builder_tmp, sc_id) = builder.add_script_code(AUTH_SCRIPT_DL.clone());
    builder = builder_tmp;
    scritp_code_id_vec.push(sc_id);

    let (builder_tmp, sc_id) = builder.add_script_code(SECP256K1_DATA_BIN.clone());
    builder = builder_tmp;
    scritp_code_id_vec.push(sc_id);

    // gen max users
    let mut max_id: u32 = 0;
    for c in &cells {
        for u in &c.users {
            if u.id > max_id {
                max_id = u.id;
            }
        }
    }
    max_id += 1;

    let mut user_id_vec: Vec<UserID> = Vec::new();
    for _i in 0..max_id {
        let (builder_tmp, userid) = builder.gen_user();
        builder = builder_tmp;
        user_id_vec.push(userid);
    }

    let mut cell_id_vec: Vec<CellID> = Vec::new();
    for cell in cells {
        let mut tx_users: Vec<TXUser> = Vec::new();
        for user in cell.users {
            tx_users.push(TXUser {
                index: user_id_vec[user.id as usize],
                nonce: user.n,
                amount: user.a,
            })
        }
        let (builder_tmp, cid) = builder.add_cell(
            scritp_code_id_vec[cell.lock_scritp as usize],
            scritp_code_id_vec[cell.type_scritp as usize],
            cell.i_amount,
            cell.o_amount,
            tx_users,
        );
        builder = builder_tmp;
        cell_id_vec.push(cid);
    }

    for tx in transfers {
        let target_type = if tx.tt == 1 {
            WitnessTransferTargetType::ScritpHash
        } else if tx.tt == 2 {
            WitnessTransferTargetType::Identity
        } else if tx.tt == 3 {
            WitnessTransferTargetType::Between
        } else {
            WitnessTransferTargetType::None
        };

        let (builder_tmp, _tid) = builder.add_transfer(TXTransfer {
            source_cell: cell_id_vec[tx.sc as usize],
            source_id: user_id_vec[tx.sd as usize],
            target_cell: cell_id_vec[tx.tc as usize],
            target_id: user_id_vec[tx.td as usize],
            target_type: target_type,
            amount: tx.a,
            fee: tx.fee,
        });
        builder = builder_tmp;
    }

    builder
}
