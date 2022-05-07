
# invoke it from root folder:
# make -f tests/taproot_lock/exec_script.Makefile all-via-docker

TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-std-lib -I deps/ckb-c-std-lib/libc -I deps/ckb-c-std-lib/molecule -I c -I build -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h
SECP256K1_SRC_20210801 := deps/secp256k1-20210801/src/ecmult_static_pre_context.h

TAPROOT_LOCK_CFLAGS := $(subst ckb-c-std-lib,ckb-c-stdlib-20210801,$(CFLAGS)) -I deps/sparse-merkle-tree/c
TAPROOT_LOCK_CFLAGS := $(subst secp256k1,secp256k1-20210801,$(TAPROOT_LOCK_CFLAGS))

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all: build/exec_script_0 build/example_script

all-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make -f tests/taproot_lock/exec_script.Makefile all"

build/exec_script_0: tests/taproot_lock/exec_script_0.c
	$(CC) $(TAPROOT_LOCK_CFLAGS) $(LDFLAGS) -o $@ $<
	cp $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/example_script: tests/taproot_lock/example_script.c
	$(CC) $(TAPROOT_LOCK_CFLAGS) $(LDFLAGS) -o $@ $<
	cp $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

clean:
	rm -rf build/exec_script_0
	rm -rf build/example_script