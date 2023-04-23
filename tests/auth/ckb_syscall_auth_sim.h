// note, this macro must be same as in ckb_syscall.h
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#undef ASSERT
#include <assert.h>
#define ASSERT assert

int ckb_exit(int8_t code) {
  exit(code);
  return 0;
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) { return 0; }

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source);

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source);

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source);

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) { return 0; }

int ckb_checked_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  return 0;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  return 0;
}

int ckb_checked_load_witness(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source) {
  return 0;
}

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset) {
  return 0;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) { return 0; }

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  if (source == CKB_SOURCE_CELL_DEP && field == CKB_CELL_FIELD_DATA_HASH) {
    if (index == 1111) {
      static uint8_t ckb_secp256k1_data_hash[32] = {
          151, 153, 190, 226, 81,  185, 117, 184, 44, 69,  160,
          33,  84,  206, 40,  206, 200, 156, 88,  83, 236, 193,
          77,  18,  183, 184, 204, 207, 193, 158, 10, 244};
      memcpy(addr, ckb_secp256k1_data_hash, 32);
    } else {
      memset(addr, 0, 32);
    }
    return 0;
  }
  return -1;
}

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field);

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
  return 0;
}

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source);

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  if (source == CKB_SOURCE_CELL_DEP && index == 1111) {
    ASSERT(*len == 1048576);
    FILE* input = fopen("build/secp256k1_data", "rb");
    if (input == NULL) {
      printf(
          "please set current directory to the root of project: "
          "ckb-production-scripts");
      return -2;
    }
    size_t read_item = fread(addr, *len, 1, input);
    ASSERT(read_item == 1);
    return 0;
  }
  return -1;
}

int ckb_checked_load_cell_data(void* addr, uint64_t* len, size_t offset,
                               size_t index, size_t source) {
  return ckb_load_cell_data(addr, len, offset, index, source);
}

int ckb_debug(const char* s);

/* load the actual witness for the current type verify group.
   use this instead of ckb_load_witness if type contract needs args to verify
   input/output.
 */
int load_actual_type_witness(uint8_t* buf, uint64_t* len, size_t index,
                             size_t* type_source);

int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index);

int ckb_calculate_inputs_len() { return 1; }

int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field) {
  return 0;
}

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index) {
  return 0;
}

int simulator_main(int argc, char* argv[]);
int ckb_exec_cell(const uint8_t* code_hash, uint8_t hash_type, uint32_t offset,
                  uint32_t length, int argc, const char* argv[]) {
  return simulator_main(argc, (char**)argv);
}

int ckb_spawn_cell(uint64_t memory_limit, const uint8_t* code_hash,
                   uint8_t hash_type, uint32_t offset, uint32_t length,
                   int argc, const char* argv[], int8_t* exit_code,
                   uint8_t* content, uint64_t* content_length) {
  return simulator_main(argc, (char**)argv);
}

int ckb_dlopen2(const uint8_t* dep_cell_hash, uint8_t hash_type,
                uint8_t* aligned_addr, size_t aligned_size, void** handle,
                size_t* consumed_size) {
  return 0;
}

void* ckb_dlsym(void* handle, const char* symbol) { return 0; }

#undef ASSERT
#define ASSERT(s) (void)0

#endif
