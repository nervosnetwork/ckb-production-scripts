OS = Unknown
ifneq ($(shell uname -a | grep -i Darwin),)
	OS = MacOS
endif
ifneq ($(shell uname -a | grep -i Linux),)
	OS = Linux
endif
ifeq ($(OS),Unknown)
	echo "error: unsupported OS"; exit 1
endif

NPROC?=4
CC=clang
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov

CORPUS_DIR=corpus

FUZZER_FLAGS=-g -O1 -fsanitize=fuzzer,address,undefined -I ../../deps/ckb-c-stdlib-simulator-only -Wno-incompatible-pointer-types

COVERAGE_DIR=coverage
COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping -I ../../deps/ckb-c-stdlib-simulator-only -Wno-incompatible-pointer-types

ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

EXTERNAL_HEADERS=../../deps/ckb-c-stdlib-simulator-only/ckb_dlfcn.h ../../deps/ckb-c-stdlib-simulator-only/ckb_consts.h ../../deps/ckb-c-stdlib-simulator-only/ckb_syscall_apis.h

all: fuzzer coverage

show: $(COVERAGE_DIR)/fuzzer.profdata
	$(LLVM_COV) show --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata dlopen_coverage

report: $(COVERAGE_DIR)/fuzzer.profdata coverage $(EXTERNAL_HEADERS)
	$(LLVM_COV) report --show-functions --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata dlopen_coverage $(EXTERNAL_HEADERS)

fuzzer:
	clang $(FUZZER_FLAGS) dlopen_fuzzer.c -o dlopen_fuzzer
	
coverage: $(EXTERNAL_HEADERS)
	clang $(COVERAGE_FLAGS) dlopen_coverage.c dlopen_fuzzer.c -o dlopen_coverage

start-fuzzer: fuzzer
	./dlopen_fuzzer -workers=$(NPROC) -jobs=$(NPROC) corpus

clean:
	rm -rf dlopen_fuzzer dlopen_coverage dlopen_fuzzer.dSYM

#%.h:
#	ln -s $(CURDIR)/../$@ $(CURDIR)/$@

%.profraw: coverage
	echo "start dlopen_coverage"
	LLVM_PROFILE_FILE=$@ ./dlopen_coverage $(CORPUS_DIR)/*

%.profdata: %.profraw
	$(LLVM_PROFDATA) merge --sparse $< -o $@

.PHONY: all fuzzer coverage report

.PRECIOUS: $(COVERAGE_DIR)/fuzzer.profraw $(COVERAGE_DIR)/fuzzer.profdata
