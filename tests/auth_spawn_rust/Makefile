CKB_DEBUGGER ?= ckb-debugger

all: \
	auth-spawn-success

auth-spawn-success:
	cargo run --bin auth-spawn-success |  ${CKB_DEBUGGER} --tx-file=- -s lock

