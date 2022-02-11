OS = Unknown
CC = clang
ifneq ($(shell uname -a | grep -i Darwin),)
	OS = MacOS
endif
ifneq ($(shell uname -a | grep -i Linux),)
	OS = Linux
endif
ifeq ($(OS),Unknown)
	echo "error: unsupported OS"; exit 1
endif

NPROC?=16
CC=clang
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov

CORPUS_DIR=corpus

FUZZER_FLAGS=-g -O3 -fsanitize=fuzzer,address,undefined -I.. -I../../../c -I../../../c/nanocbor -I../../../deps/ed25519/src -DCKB_SIMULATOR -DCKB_DECLARATION_ONLY -DCKB_USE_SIM

COVERAGE_DIR=coverage
COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping -I.. -I../../../c -I../../../c/nanocbor -I../../../deps/ed25519/src -DCKB_SIMULATOR -DCKB_DECLARATION_ONLY -DCKB_USE_SIM

ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

EXTERNAL_HEADERS=../../../c/cardano_lock_inc.h

NANOCBOR_FILES=../../../c/nanocbor/decoder.c ../../../c/nanocbor/encoder.c

all: fuzzer coverage

show: $(COVERAGE_DIR)/fuzzer.profdata
	$(LLVM_COV) show --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata cardano_coverage

report: $(COVERAGE_DIR)/fuzzer.profdata coverage $(EXTERNAL_HEADERS)
	$(LLVM_COV) report --show-functions --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata cardano_coverage $(EXTERNAL_HEADERS)

fuzzer: cardano_fuzzer.c $(NANOCBOR_FILES)
	clang $(FUZZER_FLAGS) $^ -o cardano_fuzzer 

coverage: cardano_coverage.c cardano_fuzzer.c $(NANOCBOR_FILES)
	clang $(COVERAGE_FLAGS) $^ -o cardano_coverage

start-fuzzer: fuzzer
	./cardano_fuzzer -max_len=8000 -workers=$(NPROC) -jobs=$(NPROC) corpus

start-fuzzer2: fuzzer
	./cardano_fuzzer -max_len=800000 corpus

clean:
	rm -rf cardano_fuzzer cardano_coverage cardano_fuzzer.dSYM obj

#%.h:
#	ln -s $(CURDIR)/../$@ $(CURDIR)/$@

%.profraw: coverage
	LLVM_PROFILE_FILE=$@ ./cardano_coverage $(CORPUS_DIR)/*

%.profdata: %.profraw
	$(LLVM_PROFDATA) merge --sparse $< -o $@

.PHONY: all fuzzer coverage report

.PRECIOUS: $(COVERAGE_DIR)/fuzzer.profraw $(COVERAGE_DIR)/fuzzer.profdata
