CORPUS_DIR=corpus
COVERAGE_DIR=coverage
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov
RSA_COVERAGE=cmake-build-debug/rsa_coverage
EXTERNAL_HEADERS=../../../c/validate_signature_rsa.c

show: $(COVERAGE_DIR)/fuzzer.profdata
	$(LLVM_COV) show --name=mpi_mul_hlp2 --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata $(RSA_COVERAGE)

report: $(COVERAGE_DIR)/fuzzer.profdata $(EXTERNAL_HEADERS)
	$(LLVM_COV) report --show-functions --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata $(RSA_COVERAGE) $(EXTERNAL_HEADERS)

%.profraw: $(RSA_COVERAGE)
	LLVM_PROFILE_FILE=$@ $(RSA_COVERAGE) $(CORPUS_DIR)/*

%.profdata: %.profraw
	$(LLVM_PROFDATA) merge --sparse $< -o $@

.PHONY: all report show

.PRECIOUS: $(COVERAGE_DIR)/fuzzer.profraw $(COVERAGE_DIR)/fuzzer.profdata
