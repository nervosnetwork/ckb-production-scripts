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

FUZZER_FLAGS=-g -O1 -fsanitize=fuzzer,address,undefined -fsanitize-recover=address -I ../../../c -I ../../../deps/ckb-c-stdlib-add-identity

COVERAGE_DIR=coverage
COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping -I ../../../c -I ../../../deps/ckb-c-stdlib-add-identity

ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

EXTERNAL_HEADERS=../../../deps/ckb-c-stdlib-add-identity/ckb_exec.h

all: fuzzer coverage

show: $(COVERAGE_DIR)/fuzzer.profdata
	$(LLVM_COV) show --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata exec_coverage

report: $(COVERAGE_DIR)/fuzzer.profdata coverage $(EXTERNAL_HEADERS)
	$(LLVM_COV) report --show-functions --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata exec_coverage $(EXTERNAL_HEADERS)

fuzzer: $(EXTERNAL_HEADERS)
	clang  $(FUZZER_FLAGS) exec_fuzzer.c -o exec_fuzzer

coverage: $(EXTERNAL_HEADERS)
	clang $(COVERAGE_FLAGS) exec_coverage.c exec_fuzzer.c -o exec_coverage

start-fuzzer: fuzzer
	ASAN_OPTIONS=halt_on_error=0 ./exec_fuzzer -max_len=50000 -len_control=2 -workers=$(NPROC) -jobs=$(NPROC) corpus

start-fuzzer2: fuzzer
	./exec_fuzzer -max_len=50000 -len_control=2 corpus

clean:
	rm -rf exec_fuzzer exec_coverage exec_fuzzer.dSYM

#%.h:
#	ln -s $(CURDIR)/../$@ $(CURDIR)/$@

%.profraw: coverage
	LLVM_PROFILE_FILE=$@ ./exec_coverage $(CORPUS_DIR)/*

%.profdata: %.profraw
	$(LLVM_PROFDATA) merge --sparse $< -o $@

.PHONY: all fuzzer coverage report

.PRECIOUS: $(COVERAGE_DIR)/fuzzer.profraw $(COVERAGE_DIR)/fuzzer.profdata
