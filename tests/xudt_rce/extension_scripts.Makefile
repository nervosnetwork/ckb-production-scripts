
# invoke it from root folder:
# make -f tests/xudt_rce/extension_scripts.Makefile all-via-docker

TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy

CFLAGS := -fPIC -Os -fno-builtin-printf -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -I deps/ckb-c-std-lib -I deps/ckb-c-std-lib/molecule -I deps/ckb-c-std-lib/libc -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function
OWNER_SCRIPT_CFLAGS := $(subst ckb-c-std-lib,ckb-c-stdlib-20210801,$(CFLAGS)) -I c -I deps/secp256k1-20210801 -I deps/secp256k1-20210801/src -I build -I deps/sparse-merkle-tree/c
LDFLAGS := -Wl,-static -Wl,--gc-sections
MOLC := moleculec
MOLC_VERSION := 0.7.0


# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all: build/extension_script_0 build/extension_script_1 build/owner_script

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make -f tests/xudt_rce/extension_scripts.Makefile"

build/extension_script_0: tests/xudt_rce/extension_script_0.c
	$(CC) $(CFLAGS) $(LDFLAGS) -D__SHARED_LIBRARY__ -fPIC -fPIE -pie -Wl,--dynamic-list tests/xudt_rce/validate.syms -o $@ $^

build/extension_script_1: tests/xudt_rce/extension_script_1.c
	$(CC) $(CFLAGS) $(LDFLAGS) -D__SHARED_LIBRARY__ -fPIC -fPIE -pie -Wl,--dynamic-list tests/xudt_rce/validate.syms -o $@ $^

build/owner_script: tests/xudt_rce/owner_script.c
	$(CC) $(OWNER_SCRIPT_CFLAGS) $(LDFLAGS) -D__SHARED_LIBRARY__ -fPIC -fPIE -pie -Wl,--dynamic-list tests/xudt_rce/validate.syms -o $@ $^

mol: src/tests/xudt_rce_mol.rs src/tests/blockchain.rs

src/tests/xudt_rce_mol.rs: c/xudt_rce.mol
	${MOLC} --language rust --schema-file $< | rustfmt > $@

src/tests/blockchain.rs: c/blockchain.mol
	${MOLC} --language rust --schema-file $< | rustfmt > $@


clean:
	rm -rf build/extension_script_0
	rm -rf build/extension_script_1
	rm -rf build/owner_script

dist: clean all

.PHONY: all all-via-docker dist clean
