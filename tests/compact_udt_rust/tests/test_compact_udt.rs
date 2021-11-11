use ckb_types::packed::Byte32;
use compact_udt_rust::{CellID, TXBuilder, UserID};
mod misc;
use misc::*;

// script id:
//  0: compact_udt
//  1: sudt
//  2: always_success
//  3: xudt

fn get_test_data_signle() -> (Vec<MiscCellData>, Vec<MiscTransferData>) {
    #[rustfmt::skip]
    let cells_data = vec![MiscCellData {
        lock_scritp: 0,
        type_scritp: 1,
        enable_identity: true,
        i_amount: 10000,
        o_amount: 100,
        users: vec![
            MiscUserData {id: 0, n: 20, a: 10  },
            MiscUserData {id: 1, n: 30, a: 100 },
            MiscUserData {id: 2, n: 12, a: 500 },
            MiscUserData {id: 3, n: 55, a: 10  },
        ],
    }];

    #[rustfmt::skip]
    let transfer_data = vec![
        MiscTransferData {sc: 0, sd: 0, tc: 0, td: 2, tt: 2, a: 5,  fee: 1 },
        MiscTransferData {sc: 0, sd: 1, tc: 0, td: 3, tt: 2, a: 10, fee: 1 },
    ];
    (cells_data, transfer_data)
}

fn get_test_data_mulit() -> (Vec<MiscCellData>, Vec<MiscTransferData>) {
    #[rustfmt::skip]
    let cells_data = vec![
        MiscCellData {
            lock_scritp: 0,
            type_scritp: 1,
            enable_identity: true,
            i_amount: 10000,
            o_amount: 100,
            users: vec![
                MiscUserData {id: 0, n: 20, a: 10  },
                MiscUserData {id: 1, n: 30, a: 100 },
                MiscUserData {id: 2, n: 12, a: 500 },
                MiscUserData {id: 3, n: 55, a: 10  },
            ],
        },
        MiscCellData {
            lock_scritp: 2,
            type_scritp: 3,
            enable_identity: false,
            i_amount: 50000,
            o_amount: 300,
            users: vec![
                MiscUserData {id: 0, n: 44, a: 100 },
                MiscUserData {id: 2, n: 32, a: 100 },
                MiscUserData {id: 4, n: 12, a: 50  },
                MiscUserData {id: 5, n: 3,  a: 300 },
            ],
        },
        MiscCellData {
            lock_scritp: 0,
            type_scritp: 1,
            enable_identity: true,
            i_amount: 50000,
            o_amount: 10000,
            users: vec![
                MiscUserData {id: 2, n: 333, a: 100  },
                MiscUserData {id: 4, n: 123, a: 1100 },
                MiscUserData {id: 6, n: 45,  a: 5000 },
            ],
        },
        MiscCellData {
            lock_scritp: 0,
            type_scritp: 1,
            enable_identity: false,
            i_amount: 12220,
            o_amount: 2000,
            users: vec![
                MiscUserData {id: 3, n: 23, a: 300  },
                MiscUserData {id: 4, n: 89, a: 2000 },
                MiscUserData {id: 5, n: 76, a: 100  },
                MiscUserData {id: 6, n: 72, a: 1000 },
            ],
        },
    ];

    #[rustfmt::skip]
    let transfer_data = vec![
        MiscTransferData {sc: 0, sd: 0, tc: 1, td: 2, tt: 1, a: 50,  fee: 1  },
        MiscTransferData {sc: 0, sd: 2, tc: 0, td: 0, tt: 2, a: 300, fee: 1  },
        MiscTransferData {sc: 1, sd: 2, tc: 2, td: 6, tt: 3, a: 1,   fee: 10 },
        MiscTransferData {sc: 1, sd: 0, tc: 1, td: 2, tt: 2, a: 10,  fee: 10 },
        MiscTransferData {sc: 2, sd: 4, tc: 0, td: 0, tt: 3, a: 1000,fee: 10 },
        MiscTransferData {sc: 0, sd: 0, tc: 2, td: 6, tt: 3, a: 20,  fee: 30 },
        MiscTransferData {sc: 1, sd: 2, tc: 3, td: 5, tt: 3, a: 99,  fee: 30 },
    ];
    (cells_data, transfer_data)
}

fn get_test_data_spec() -> (Vec<MiscCellData>, Vec<MiscTransferData>) {
    #[rustfmt::skip]
    let cells_data = vec![
        MiscCellData {
            lock_scritp: 0,
            type_scritp: 1,
            enable_identity: true,
            i_amount: 1000,
            o_amount: 900,
            users: vec![
                MiscUserData {id: 0, n: 5, a: 400 },    // Alice
                MiscUserData {id: 1, n: 1, a: 10  },    // Bob
            ],
        },
        MiscCellData {
            lock_scritp: 0,
            type_scritp: 1,
            enable_identity: true,
            i_amount: 400,
            o_amount: 500,
            users: vec![
                MiscUserData {id: 0, n: 4, a: 5 },  // Alice
                MiscUserData {id: 2, n: 0, a: 0 },  // Charlie
            ],
        },
    ];
    #[rustfmt::skip]
    let transfer_data = vec![
        MiscTransferData {sc: 0, sd: 0, tc: 0, td: 1, tt: 2, a: 50,  fee: 0 },
        MiscTransferData {sc: 0, sd: 0, tc: 1, td: 2, tt: 3, a: 100, fee: 0 },
        MiscTransferData {sc: 1, sd: 2, tc: 1, td: 0, tt: 2, a: 20, fee: 0 },
    ];
    (cells_data, transfer_data)
}

#[test]
fn success_single_cell() {
    let (cells_data, transfer_data) = get_test_data_signle();

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("success_single_cell");
    assert!(res.is_ok(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn success_mulit_all_cudt() {
    let (cells_data, transfer_data) = get_test_data_mulit();

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("success_mulit_all_cudt");
    assert!(res.is_ok(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn success_amount_near_overflow() {
    let (mut cells_data, transfer_data) = get_test_data_signle();

    cells_data[0].i_amount = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("success_amount_near_overflow");
    assert!(res.is_ok(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn success_from_spec() {
    let (cells_data, transfer_data) = get_test_data_spec();

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();

    let cell1 = tx.builder.cells.get(&CellID::new(0)).unwrap();
    let cell2 = tx.builder.cells.get(&CellID::new(1)).unwrap();

    let (alice_s_1, bob_s_1) = if cell1.output_kv_pairs[0].index == UserID::new(0) {
        // Alice
        (&cell1.output_kv_pairs[0], &cell1.output_kv_pairs[1])
    } else {
        (&cell1.output_kv_pairs[1], &cell1.output_kv_pairs[0])
    };

    let (alice_s_2, charlie_s_2) = if cell2.output_kv_pairs[0].index == UserID::new(0) {
        // Alice
        (&cell2.output_kv_pairs[0], &cell2.output_kv_pairs[1])
    } else {
        (&cell2.output_kv_pairs[1], &cell2.output_kv_pairs[0])
    };

    assert!(alice_s_1.amount == 250 && alice_s_1.nonce == 7);
    assert!(bob_s_1.amount == 60 && bob_s_1.nonce == 1);

    assert!(alice_s_2.amount == 25 && alice_s_2.nonce == 4);
    assert!(charlie_s_2.amount == 80 && charlie_s_2.nonce == 1);

    let res = tx.run();
    tx.output_json("success_from_spec");
    assert!(res.is_ok(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn failed_nonce_overflow() {
    let (mut cells_data, transfer_data) = get_test_data_signle();
    cells_data[0].users[1].n = 0xffffffff;

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("failed_nonce_overflow");
    assert!(res.is_err(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn failed_amount_overflow() {
    let (mut cells_data, transfer_data) = get_test_data_mulit();

    cells_data[3].i_amount = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("failed_amount_overflow");
    assert!(res.is_err(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn failed_out_amount_too_much() {
    let (mut cells_data, transfer_data) = get_test_data_signle();

    cells_data[0].o_amount = cells_data[0].i_amount + cells_data[0].o_amount;

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("failed_out_amount_too_much");
    assert!(res.is_err(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn failed_identity() {
    let (cells_data, transfer_data) = get_test_data_signle();

    let mut builder = TXBuilder::new();
    builder.test_data_err_pub_key = true;
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("failed_identity");
    assert!(res.is_err(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn faliled_def_user() {
    let (cells_data, transfer_data) = get_test_data_signle();

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);
    let builder = builder.remove_user_output(0, 2);

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("faliled_def_user");
    assert!(res.is_err(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn failed_same_type_id() {
    let (mut cells_data, transfer_data) = get_test_data_mulit();
    cells_data[2].enable_identity = false;
    cells_data[3].enable_identity = false;

    let builder = TXBuilder::new();
    let mut builder = gen_tx_builder(builder, cells_data, transfer_data);

    for (_id, cells) in &mut builder.cells {
        if cells.lock_script_id == builder.cudt_scritp_id.unwrap() {
            cells.type_id = Byte32::new([0; 32]);
        }
    }

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("failed_same_type_id");
    assert!(res.is_err(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn failed_version() {
    let (cells_data, transfer_data) = get_test_data_mulit();

    let builder = TXBuilder::new();
    let mut builder = gen_tx_builder(builder, cells_data, transfer_data);

    for (_id, cells) in &mut builder.cells {
        if cells.lock_script_id == builder.cudt_scritp_id.unwrap() {
            cells.ver = rand::random::<u8>();
        }
    }

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("failed_version");
    assert!(res.is_err(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn failed_transfer_sign() {
    let (cells_data, transfer_data) = get_test_data_signle();

    let builder = TXBuilder::new();
    let mut builder = gen_tx_builder(builder, cells_data, transfer_data);
    builder.test_data_err_transfer_sign = true;

    let tx = builder.build();
    let res = tx.run();
    tx.output_json("failed_transfer_sign");
    assert!(res.is_err(), "error: {}", res.unwrap_err().to_string());
}
