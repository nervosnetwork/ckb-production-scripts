
# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3
CLANG_FORMAT_DOCKER := kason223/clang-format@sha256:3cce35b0400a7d420ec8504558a02bdfc12fd2d10e40206f140c4545059cd95d

ALL_C_SOURCE := c/auth.c c/ckb_auth.h\
				tests/auth/auth_sim.c tests/auth/ckb_syscall_auth_sim.h

fmt:
	docker run --rm -v `pwd`/../..:/code ${CLANG_FORMAT_DOCKER} bash -c "cd code && clang-format -i -style=Google $(ALL_C_SOURCE)"
