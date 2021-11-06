use compact_udt_rust::TXBuilder;
mod misc;
use misc::*;

// script id:
//  0: compact_udt
//  1: sudt
//  2: always_success

#[test]
fn success_single_cell() {
    #[rustfmt::skip]
    let cells_data = vec![MiscCellData {
        lock_scritp: 0,
        type_scritp: 1,
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

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run(false);
    assert!(res.is_ok(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn success_mulit_all_cudt() {
    #[rustfmt::skip]
    let cells_data = vec![
        MiscCellData {
            lock_scritp: 0,
            type_scritp: 1,
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
            lock_scritp: 0,
            type_scritp: 3,
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
        MiscTransferData {sc: 0, sd: 0, tc: 1, td: 2, tt: 3, a: 50,  fee: 1  },
        MiscTransferData {sc: 0, sd: 2, tc: 0, td: 0, tt: 2, a: 300, fee: 1  },
        MiscTransferData {sc: 1, sd: 2, tc: 2, td: 6, tt: 3, a: 1,   fee: 10 },
        MiscTransferData {sc: 1, sd: 0, tc: 1, td: 2, tt: 2, a: 10,  fee: 10 },
        MiscTransferData {sc: 2, sd: 4, tc: 0, td: 0, tt: 3, a: 1000,fee: 10 },
        MiscTransferData {sc: 0, sd: 0, tc: 2, td: 6, tt: 3, a: 20,  fee: 30 },
        MiscTransferData {sc: 1, sd: 2, tc: 3, td: 5, tt: 3, a: 99,  fee: 30 },
    ];

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run(false);
    assert!(res.is_ok(), "error: {}", res.unwrap_err().to_string());
}

#[test]
fn success_mixed_cell() {
    #[rustfmt::skip]
    let cells_data = vec![
        MiscCellData {
            lock_scritp: 0,
            type_scritp: 1,
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
            type_scritp: 1,
            i_amount: 20000,
            o_amount: 300,
            users: vec![],
        },
    ];
    
    #[rustfmt::skip]
    let transfer_data = vec![
        MiscTransferData {sc: 0, sd: 0, tc: 0, td: 2, tt: 2, a: 5,   fee: 1 },
        MiscTransferData {sc: 0, sd: 1, tc: 0, td: 3, tt: 2, a: 10,  fee: 1 },
        MiscTransferData {sc: 1, sd: 0, tc: 0, td: 3, tt: 2, a: 100, fee: 2 },
    ];

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run(false);
    assert!(res.is_ok(), "error: {}", res.unwrap_err().to_string());
}

// TODO failed and success xudt
#[test]
fn failed_mixed_cell() {
    #[rustfmt::skip]
    let cells_data = vec![
        MiscCellData {
            lock_scritp: 0,
            type_scritp: 1,
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
            type_scritp: 1,
            i_amount: 20000,
            o_amount: 100000,
            users: vec![],
        },
    ];
    
    #[rustfmt::skip]
    let transfer_data = vec![
        MiscTransferData {sc: 0, sd: 0, tc: 0, td: 2, tt: 2, a: 5,   fee: 1 },
        MiscTransferData {sc: 0, sd: 1, tc: 0, td: 3, tt: 2, a: 10,  fee: 1 },
        MiscTransferData {sc: 1, sd: 0, tc: 0, td: 3, tt: 2, a: 100, fee: 2 },
    ];

    let builder = TXBuilder::new();
    let builder = gen_tx_builder(builder, cells_data, transfer_data);

    let tx = builder.build();
    let res = tx.run(true);
    assert!(res.is_err(), "error: {}", res.unwrap_err().to_string());
}

