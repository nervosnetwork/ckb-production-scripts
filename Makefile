TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-std-lib -I deps/ckb-c-std-lib/libc -I deps/ckb-c-std-lib/molecule -I c -I build -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h
XUDT_RCE_CFLAGS=$(subst ckb-c-std-lib,ckb-c-stdlib-20210713,$(CFLAGS)) -I deps/sparse-merkle-tree/c
AUTH_CFLAGS=$(subst ckb-c-std-lib,ckb-c-stdlib-20210917,$(CFLAGS)) -I deps/mbedtls/include

PROTOCOL_HEADER := c/blockchain.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol
MOLC := moleculec
MOLC_VERSION := 0.7.0

# RSA/mbedtls
CFLAGS_MBEDTLS := $(subst ckb-c-std-lib,ckb-c-stdlib-20210413,$(CFLAGS)) -I deps/mbedtls/include
LDFLAGS_MBEDTLS := $(LDFLAGS)
PASSED_MBEDTLS_CFLAGS := -O3 -fPIC -nostdinc -nostdlib -DCKB_DECLARATION_ONLY -I ../../ckb-c-stdlib-20210413/libc -fdata-sections -ffunction-sections

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all: build/simple_udt build/anyone_can_pay build/always_success build/validate_signature_rsa build/xudt_rce build/rce_validator build/auth

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

build/simple_udt: c/simple_udt.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/anyone_can_pay: c/anyone_can_pay.c ${PROTOCOL_HEADER} c/secp256k1_lock.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/always_success: c/always_success.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc -I deps/secp256k1/src -I deps/secp256k1 -o $@ $<

$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

deps/mbedtls/library/libmbedcrypto.a:
	cp deps/mbedtls-config-template.h deps/mbedtls/include/mbedtls/config.h
	make -C deps/mbedtls/library CC=${CC} LD=${LD} CFLAGS="${PASSED_MBEDTLS_CFLAGS}" libmbedcrypto.a

build/impl.o: deps/ckb-c-std-lib/libc/src/impl.c
	$(CC) -c $(filter-out -DCKB_DECLARATION_ONLY, $(CFLAGS_MBEDTLS)) $(LDFLAGS_MBEDTLS) -o $@ $^

validate_signature_rsa-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make build/validate_signature_rsa"

build/validate_signature_rsa: c/validate_signature_rsa.c deps/mbedtls/library/libmbedcrypto.a
	$(CC) $(CFLAGS_MBEDTLS) $(LDFLAGS_MBEDTLS) -D__SHARED_LIBRARY__ -fPIC -fPIE -pie -Wl,--dynamic-list c/rsa.syms -o $@ $^
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

validate_signature_rsa_sim-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make build/validate_signature_rsa_sim"

# for test only
CFLAGS_MBEDTLS2:=$(filter-out -Werror,$(CFLAGS_MBEDTLS))
CFLAGS_MBEDTLS2:=$(filter-out -Wno-nonnull,$(CFLAGS_MBEDTLS2))
CFLAGS_MBEDTLS2:=$(filter-out -Wno-nonnull-compare,$(CFLAGS_MBEDTLS2))
CFLAGS_MBEDTLS2:=$(filter-out -Wno-unused-function,$(CFLAGS_MBEDTLS2))
CFLAGS_MBEDTLS2:=$(filter-out -Wall,$(CFLAGS_MBEDTLS2))
build/validate_signature_rsa_sim: tests/validate_signature_rsa/validate_signature_rsa_sim.c deps/mbedtls/library/libmbedcrypto.a
	$(CC) $(CFLAGS_MBEDTLS2) $(LDFLAGS_MBEDTLS) -DCKB_RUN_IN_VM -o $@ $^


validate_signature_rsa_clean:
	make -C deps/mbedtls/library clean
	rm -f build/validate_signature_rsa
	rm -f build/*.o

### Auth
build/auth: c/auth.c deps/mbedtls/library/libmbedcrypto.a
	$(CC) $(AUTH_CFLAGS) $(LDFLAGS) -fPIC -fPIE -pie -Wl,--dynamic-list c/auth.syms -o $@ $^
	cp $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

${PROTOCOL_SCHEMA}:
	curl -L -o $@ ${PROTOCOL_URL}

fmt:
	clang-format -i -style=Google $(wildcard c/rce_validator.c /always_success.c c/anyone_can_pay.c c/smt.h c/rce.h c/xudt_rce.c c/rce_validator.c tests/xudt_rce/*.c tests/xudt_rce/*.h)
	git diff --exit-code $(wildcard c/rce_validator.c /always_success.c c/anyone_can_pay.c c/smt.h c/rce.h c/xudt_rce.c tests/xudt_rce/*.c tests/xudt_rce/*.h)

mol:
	rm -f c/xudt_rce_mol.h
	rm -f c/xudt_rce_mol2.h
	rm -f xudt/src/xudt_rce_mol.rs
	make c/xudt_rce_mol.h
	make c/xudt_rce_mol2.h
	make xudt/src/xudt_rce_mol.rs


xudt/src/xudt_rce_mol.rs: c/xudt_rce.mol
	${MOLC} --language rust --schema-file $< | rustfmt > $@

c/xudt_rce_mol.h: c/xudt_rce.mol
	${MOLC} --language c --schema-file $< > $@

c/xudt_rce_mol2.h: c/xudt_rce.mol
	moleculec --language - --schema-file c/xudt_rce.mol --format json > build/blockchain_mol2.json
	moleculec-c2 --input build/blockchain_mol2.json | clang-format -style=Google > c/xudt_rce_mol2.h

build/xudt_rce: c/xudt_rce.c c/rce.h
	$(CC) $(XUDT_RCE_CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/rce_validator: c/rce_validator.c c/rce.h
	$(CC) $(XUDT_RCE_CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

publish:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo publish --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo package --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package-clean:
	git checkout Cargo.toml Cargo.lock
	rm -rf Cargo.toml.bak target/package/

clean:
	rm -rf build/simple_udt
	rm -rf build/anyone_can_pay
	rm -rf build/secp256k1_data_info.h build/dump_secp256k1_data
	rm -rf build/secp256k1_data
	rm -rf build/*.debug
	rm -f build/xudt_rce
	rm -f build/rce_validator
	cd deps/secp256k1 && [ -f "Makefile" ] && make clean
	make -C deps/mbedtls/library clean
	rm -f build/validate_signature_rsa
	rm -f build/validate_signature_rsa_sim
	rm -f build/auth build/auth_demo
	cargo clean

install-tools:
	if [ ! -x "$$(command -v "${MOLC}")" ] \
			|| [ "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" != "${MOLC_VERSION}" ]; then \
		cargo install --force --version "${MOLC_VERSION}" "${MOLC}"; \
	fi

dist: clean all

.PHONY: all all-via-docker dist clean package-clean package publish
