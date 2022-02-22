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

ED25519_PATH=../../../deps/ed25519/src/
CFLAG_INC_PATH=-I.. -I../../../c -I$(ED25519_PATH)
CFLAG_DEFINED=-DCKB_SIMULATOR -DCKB_DECLARATION_ONLY -DCKB_USE_SIM

FUZZER_FLAGS=-g -O1 -fsanitize=fuzzer,address $(CFLAG_INC_PATH) $(CFLAG_DEFINED)

COVERAGE_DIR=coverage
COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping $(CFLAG_INC_PATH) $(CFLAG_DEFINED)

ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

ED25519_FILES=$(ED25519_PATH)verify.c $(ED25519_PATH)sha512.c $(ED25519_PATH)sc.c $(ED25519_PATH)ge.c $(ED25519_PATH)fe.c

all: fuzzer coverage

show: $(COVERAGE_DIR)/fuzzer.profdata
	$(LLVM_COV) show --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata ed25519_coverage

report: $(COVERAGE_DIR)/fuzzer.profdata coverage $(EXTERNAL_HEADERS)
	$(LLVM_COV) report --show-functions --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata ed25519_coverage $(EXTERNAL_HEADERS)

fuzzer: ed25519_fuzzer.c $(ED25519_FILES)
	clang $(FUZZER_FLAGS) $^ -o ed25519_fuzzer 

coverage: ed25519_coverage.c ed25519_fuzzer.c $(ED25519_FILES)
	clang $(COVERAGE_FLAGS) $^ -o ed25519_coverage

start-fuzzer: fuzzer
	mkdir corpus
	./ed25519_fuzzer -max_len=8000 -workers=$(NPROC) -jobs=$(NPROC) corpus

start-fuzzer2: fuzzer
	./ed25519_fuzzer -max_len=800000 corpus

clean:
	rm -rf ed25519_fuzzer ed25519_coverage ed25519_fuzzer.dSYM obj

%.profraw: coverage
	LLVM_PROFILE_FILE=$@ ./ed25519_coverage $(CORPUS_DIR)/*

%.profdata: %.profraw
	$(LLVM_PROFDATA) merge --sparse $< -o $@

.PHONY: all fuzzer coverage report

.PRECIOUS: $(COVERAGE_DIR)/fuzzer.profraw $(COVERAGE_DIR)/fuzzer.profdata
