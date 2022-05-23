#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_script::cost_model::transferred_byte_cycles;
use ckb_script::{ScriptGroup, ScriptGroupType, ScriptVersion, TransactionScriptsVerifier};
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::bytes::Bytes;
use ckb_types::packed::Byte32;
use ckb_vm::machine::asm::{AsmCoreMachine, AsmMachine};
use ckb_vm::{DefaultMachineBuilder, SupportMachine};
use ckb_vm_debug_utils::{GdbHandler, Stdio};
use gdb_remote_protocol::process_packets_from;
use std::net::TcpListener;

/*
* addr: the address listening on, e.g. 127.0.0.1:9999
* script_group: the script_group (type/lock) to run
* program: bytes of risc-v binary which must contain debug information
* args: arguments passed to script
* verifier:
*/
pub fn debug<'a, DL: CellDataProvider + HeaderProvider>(
    addr: &str,
    script_type: ScriptGroupType,
    script_hash: Byte32,
    program: &Bytes,
    args: &[Bytes],
    verifier: &TransactionScriptsVerifier<'a, DL>,
) {
    let script_group = get_script_group(&verifier, script_type, &script_hash).unwrap();

    // GDB path
    let listener = TcpListener::bind(addr).expect("listen");
    let script_version = ScriptVersion::V1;
    let max_cycle = 70_000_000u64;

    for res in listener.incoming() {
        if let Ok(stream) = res {
            let core_machine = AsmCoreMachine::new(
                script_version.vm_isa(),
                script_version.vm_version(),
                max_cycle,
            );
            let builder = DefaultMachineBuilder::new(core_machine)
                .instruction_cycle_func(verifier.cost_model())
                .syscall(Box::new(Stdio::new(true)));
            let builder = verifier
                .generate_syscalls(script_version, script_group)
                .into_iter()
                .fold(builder, |builder, syscall| builder.syscall(syscall));
            let mut machine = AsmMachine::new(builder.build(), None);
            let bytes = machine.load_program(&program, args).expect("load program");
            machine
                .machine
                .add_cycles(transferred_byte_cycles(bytes))
                .expect("load program cycles");
            machine.machine.set_running(true);
            let h = GdbHandler::new(machine);
            process_packets_from(stream.try_clone().unwrap(), stream, h);
        }
    }
}

fn get_script_group<'a, DL: CellDataProvider + HeaderProvider>(
    verifier: &'a TransactionScriptsVerifier<'a, DL>,
    group_type: ScriptGroupType,
    hash: &Byte32,
) -> Option<&'a ScriptGroup> {
    for (t, h, g) in verifier.groups() {
        if group_type == t && h == hash {
            return Some(g);
        }
    }
    None
}
