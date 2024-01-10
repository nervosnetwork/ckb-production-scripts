#![allow(dead_code)]

use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionView},
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
};
use rand::{thread_rng, Rng};

use misc::{
    assert_script_error, build_always_success_script, build_resolved_tx, debug_printer, gen_tx,
    sign_tx, DummyDataLoader, EthereumConfig, TestConfig, ALWAYS_SUCCESS, CKB_INVALID_DATA,
    ERROR_BURN, ERROR_EXCEED_SUPPLY, ERROR_NO_INFO_CELL, ERROR_SUPPLY_AMOUNT,
    IDENTITY_FLAGS_ETHEREUM, MAX_CYCLES, SIMPLE_UDT,
};

mod misc;

fn gen_info_cell_type_script() -> (Script, [u8; 32]) {
    let mut rng = rand::thread_rng();
    let data_hash = CellOutput::calc_data_hash(&ALWAYS_SUCCESS);
    let mut args = vec![0u8; 32];
    rng.fill(&mut args[..]);
    let script = Script::new_builder()
        .code_hash(data_hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(args).pack())
        .build();
    let script_hash = script.calc_script_hash();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(script_hash.as_slice());
    (script, hash)
}

fn gen_out_point() -> OutPoint {
    let mut rng = thread_rng();
    let previous_tx_hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    OutPoint::new(previous_tx_hash, 0)
}

fn sudt_type_script(loader: &DummyDataLoader, tx: &TransactionView) -> Script {
    let omni_lock_out_point = tx.inputs().get(0).unwrap().previous_output();
    let omni_lock_hash = loader
        .cells
        .get(&omni_lock_out_point)
        .map(|(output, _)| output.lock().calc_script_hash())
        .unwrap();
    let data_hash = CellOutput::calc_data_hash(&SIMPLE_UDT);
    Script::new_builder()
        .code_hash(data_hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .args(omni_lock_hash.as_bytes().pack())
        .build()
}

fn add_sudt_to_inputs(
    loader: &mut DummyDataLoader,
    sudt_type_script: Script,
    tx: TransactionView,
    amount: u128,
) -> TransactionView {
    let previous_output = CellOutput::new_builder()
        .capacity(42.pack())
        .type_(Some(sudt_type_script).pack())
        .lock(build_always_success_script())
        .build();
    let previous_data = Bytes::from(amount.to_le_bytes().to_vec());
    let previous_out_point = gen_out_point();
    loader
        .cells
        .insert(previous_out_point.clone(), (previous_output, previous_data));
    tx.as_advanced_builder()
        .input(CellInput::new(previous_out_point, 0))
        .build()
}

fn add_sudt_to_outputs(
    sudt_type_script: Script,
    tx: TransactionView,
    amount: u128,
) -> TransactionView {
    let output = CellOutput::new_builder()
        .capacity(42.pack())
        .type_(Some(sudt_type_script).pack())
        .lock(build_always_success_script())
        .build();
    let data = Bytes::from(amount.to_le_bytes().to_vec());
    tx.as_advanced_builder()
        .output(output)
        .output_data(data.pack())
        .build()
}

fn add_sudt_dep(loader: &mut DummyDataLoader, tx: TransactionView) -> TransactionView {
    let dep_out_point = gen_out_point();
    let sudt_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(SIMPLE_UDT.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    loader
        .cells
        .insert(dep_out_point.clone(), (sudt_cell, SIMPLE_UDT.clone()));
    tx.as_advanced_builder()
        .cell_dep(
            CellDep::new_builder()
                .out_point(dep_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .build()
}

fn add_info_cell_to_inputs(
    loader: &mut DummyDataLoader,
    type_script: Script,
    tx: TransactionView,
    data: Vec<u8>,
) -> TransactionView {
    let previous_output = CellOutput::new_builder()
        .capacity(42.pack())
        .type_(Some(type_script).pack())
        .lock(build_always_success_script())
        .build();
    let previous_data = Bytes::from(data);
    let previous_out_point = gen_out_point();
    loader
        .cells
        .insert(previous_out_point.clone(), (previous_output, previous_data));
    tx.as_advanced_builder()
        .input(CellInput::new(previous_out_point, 0))
        .build()
}

fn add_info_cell_to_outputs(
    type_script: Script,
    tx: TransactionView,
    data: Vec<u8>,
) -> TransactionView {
    let output = CellOutput::new_builder()
        .capacity(42.pack())
        .type_(Some(type_script).pack())
        .lock(build_always_success_script())
        .build();
    tx.as_advanced_builder()
        .output(output)
        .output_data(Bytes::from(data).pack())
        .build()
}

fn build_info_cell_data(
    current_supply: u128,
    max_supply: u128,
    sudt_type_script_hash: &[u8],
) -> Vec<u8> {
    let version = 0u8;
    let mut data = vec![0u8; 1 + 16 + 16 + 32];
    data[0] = version;
    data[1..1 + 16].copy_from_slice(&current_supply.to_le_bytes()[..]);
    data[1 + 16..1 + 16 + 16].copy_from_slice(&max_supply.to_le_bytes()[..]);
    data[1 + 16 + 16..1 + 16 + 16 + 32].copy_from_slice(sudt_type_script_hash);
    data
}

fn run_sudt_supply_case<F>(error_code: i8, gen_tx_fn: F)
where
    F: Fn(&mut DummyDataLoader, &mut TestConfig) -> TransactionView,
{
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM, false);
    config.set_chain_config(Box::new(EthereumConfig::default()));

    let tx = gen_tx_fn(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    if error_code == 0 {
        verify_result.expect("pass verification");
    } else {
        assert_script_error(verify_result.unwrap_err(), error_code);
    }
}

// ==== SUCCESS cases ====
#[test]
fn test_success_issue_token() {
    run_sudt_supply_case(0, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

// ==== ERROR cases ====
#[test]
fn test_burn_token() {
    // CHECK2(false, ERROR_BURN);
    run_sudt_supply_case(ERROR_BURN, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_inputs(data_loader, sudt_type_script.clone(), tx, 200);
        let input_info_cell_data =
            build_info_cell_data(400, max_supply, sudt_type_script_hash.as_slice());
        let output_info_cell_data =
            build_info_cell_data(200, max_supply, sudt_type_script_hash.as_slice());
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_no_info_cell_in_inputs() {
    // CHECK2(ctx.input_info_cell_count == 1, ERROR_DUPLICATED_INFO_CELL);
    run_sudt_supply_case(ERROR_NO_INFO_CELL, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_no_info_cell_in_outputs() {
    // CHECK2(ctx.output_info_cell_count == 1, ERROR_DUPLICATED_INFO_CELL);
    run_sudt_supply_case(ERROR_NO_INFO_CELL, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx
    });
}

#[test]
fn test_too_many_info_cell_in_inputs() {
    // if (ctx->input_info_cell_count > 1) {
    //     return CKB_INVALID_DATA;
    // }
    run_sudt_supply_case(CKB_INVALID_DATA, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data.clone(),
        );
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_too_many_info_cell_in_outputs() {
    // if (ctx->output_info_cell_count > 1) {
    //     return CKB_INVALID_DATA;
    // }
    run_sudt_supply_case(CKB_INVALID_DATA, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(
            info_cell_type_script.clone(),
            tx,
            output_info_cell_data.clone(),
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_info_cell_size_not_enough() {
    // CHECK2(info_cell_len >= MIN_INFO_CELL_LEN, CKB_INVALID_DATA);
    run_sudt_supply_case(CKB_INVALID_DATA, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let mut input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let mut output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        input_info_cell_data.truncate(input_info_cell_data.len() - 1);
        output_info_cell_data.truncate(output_info_cell_data.len() - 1);
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_sudt_amount_overflow() {
    // if (*sum < *delta) {
    //     return ERROR_SUPPLY_AMOUNT;
    // }
    run_sudt_supply_case(ERROR_SUPPLY_AMOUNT, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, 20);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, u128::max_value() - 10);
        let input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let output_info_cell_data =
            build_info_cell_data(40, max_supply, sudt_type_script_hash.as_slice());
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_input_exceed_supply() {
    // CHECK2(ctx.input_current_supply <= ctx.max_supply, ERROR_EXCEED_SUPPLY);
    run_sudt_supply_case(ERROR_EXCEED_SUPPLY, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let input_info_cell_data =
            build_info_cell_data(6001, max_supply, sudt_type_script_hash.as_slice());
        let output_info_cell_data = build_info_cell_data(
            6001 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}
#[test]
fn test_output_exceed_supply() {
    // CHECK2(ctx.output_current_supply <= ctx.max_supply, ERROR_EXCEED_SUPPLY);
    run_sudt_supply_case(ERROR_EXCEED_SUPPLY, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 6001;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_wrong_supply_delta() {
    // CHECK2(temp_amount == ctx.output_current_supply, ERROR_SUPPLY_AMOUNT);
    run_sudt_supply_case(ERROR_SUPPLY_AMOUNT, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let output_info_cell_data = build_info_cell_data(
            20 + issue_amount + 2,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_info_cell_wrong_version() {
    // CHECK2(ctx.version == 0, CKB_INVALID_DATA);
    run_sudt_supply_case(CKB_INVALID_DATA, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let mut input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let mut output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        input_info_cell_data[0] = 3;
        output_info_cell_data[0] = 3;
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_info_cell_version_not_match() {
    // CHECK2(input_version == output_version, CKB_INVALID_DATA);
    run_sudt_supply_case(CKB_INVALID_DATA, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let mut input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let mut output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        input_info_cell_data[0] = 0;
        output_info_cell_data[0] = 3;
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_info_cell_length_not_match() {
    // CHECK2(input_len == output_len, CKB_INVALID_DATA);
    run_sudt_supply_case(CKB_INVALID_DATA, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let mut output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        output_info_cell_data.extend(vec![0u8; 4]);
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_info_cell_extra_data_changed() {
    // CHECK2(same == 0, CKB_INVALID_DATA);
    run_sudt_supply_case(CKB_INVALID_DATA, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let mut input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let mut output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        input_info_cell_data.extend(vec![0u8; 4]);
        output_info_cell_data.extend(vec![1u8; 4]);
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}

#[test]
fn test_info_cell_max_supply_changed() {
    // CHECK2(same == 0, CKB_INVALID_DATA);
    run_sudt_supply_case(CKB_INVALID_DATA, |data_loader, config| {
        let (info_cell_type_script, cell_id) = gen_info_cell_type_script();
        config.set_sudt_supply(cell_id);

        let mut tx = gen_tx(data_loader, config);
        let issue_amount: u128 = 336;
        let max_supply: u128 = 6000;
        let sudt_type_script = sudt_type_script(data_loader, &tx);
        let sudt_type_script_hash = sudt_type_script.calc_script_hash();
        tx = add_sudt_dep(data_loader, tx);
        tx = add_sudt_to_outputs(sudt_type_script.clone(), tx, issue_amount);
        let input_info_cell_data =
            build_info_cell_data(20, max_supply, sudt_type_script_hash.as_slice());
        let mut output_info_cell_data = build_info_cell_data(
            20 + issue_amount,
            max_supply,
            sudt_type_script_hash.as_slice(),
        );
        output_info_cell_data[17..17 + 16].copy_from_slice(&(max_supply + 3).to_le_bytes()[..]);
        tx = add_info_cell_to_inputs(
            data_loader,
            info_cell_type_script.clone(),
            tx,
            input_info_cell_data,
        );
        tx = add_info_cell_to_outputs(info_cell_type_script.clone(), tx, output_info_cell_data);
        tx
    });
}
