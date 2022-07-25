// Open Transaction
// si: signature input
// sil: signature input list
// #define CKB_C_STDLIB_PRINTF

#ifndef __OPEN_TX_H__
#define __OPEN_TX_H__

#include <blake2b.h>
#include <stdint.h>

#include "ckb_consts.h"

#define MOLECULEC_VERSION 7000
#include "blockchain.h"

#ifdef OPENTX_FUZZER
#include "ckb_syscall_opentx_fuzzer.h"
#else
#include "ckb_syscalls.h"
#endif

#ifndef BLAKE2B_BLOCK_SIZE
#define BLAKE2B_BLOCK_SIZE 32
#endif

#define OPENTX_SCRIPT_SIZE 32768
#define MAX_INPUT_SIZE 1024
#define MAX_SIL_SIZE 1024
#define MAX_FIELD_COUNT 12
#define OPENTX_BATCH_SIZE 1024
#define OPENTX_TERMINAL_COMMAND 0xF0

#undef CHECK2
#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#undef CHECK
#define CHECK(_code)    \
  do {                  \
    int code = (_code); \
    if (code != 0) {    \
      err = code;       \
      ASSERT(0);        \
      goto exit;        \
    }                   \
  } while (0)

enum OpenTxErrorCode {
  // Open transaction error code is starting from 100
  OPENTX_ERROR_UNKNOWN_COMMAND = 100,
  OPENTX_ERROR_INVALID_ARGUMENT,
  OPENTX_ERROR_ENCODING,
};

typedef struct SignatureInput {
  uint8_t command;
  uint16_t arg1;
  uint16_t arg2;
} SignatureInput;

typedef struct SyscallConfig {
  size_t id;
  size_t index;
  size_t source;
  size_t field;
} SyscallConfig;

typedef struct HashCache {
  blake2b_state state;
} HashCache;

typedef struct OpenTxWitness {
  size_t base_input_index;
  size_t base_output_index;
  uint8_t *sil;
  size_t sil_len;
  uint8_t *real_sig;
  size_t real_sig_len;
} OpenTxWitness;

int hash_cache_init(HashCache *cache) {
  int err = blake2b_init(&cache->state, BLAKE2B_BLOCK_SIZE);
  if (err != 0) return err;
  return 0;
}

/* calculate group inputs/outputs length in current lock script group */
uint64_t calculate_group_len(bool is_input) {
  uint64_t len = 0;
  /* lower bound, at least tx has one input */
  uint64_t lo = 0;
  /* higher bound */
  uint64_t hi = 4;
  int ret;

  size_t source = CKB_SOURCE_GROUP_OUTPUT;
  if (is_input) {
    source = CKB_SOURCE_GROUP_INPUT;
  }
  size_t field = CKB_CELL_FIELD_CAPACITY;
  /* try to load until failing to increase lo and hi */
  while (1) {
    ret = ckb_load_cell_by_field(NULL, &len, 0, hi, source, field);
    if (ret == CKB_SUCCESS) {
      lo = hi;
      hi *= 2;
    } else {
      break;
    }
  }

  /* now we get our lower bound and higher bound,
   count number of inputs by binary search */
  int i;
  while (lo + 1 != hi) {
    i = (lo + hi) / 2;
    ret = ckb_load_cell_by_field(NULL, &len, 0, i, source, field);
    if (ret == CKB_SUCCESS) {
      lo = i;
    } else {
      hi = i;
    }
  }

  if (ret != CKB_SUCCESS && hi == 1) {
    ret = ckb_load_cell_by_field(NULL, &len, 0, 0, source, field);
    if (ret != CKB_SUCCESS) {
      hi = 0;
    }
  }

  /* now lo is last index and hi is length of inputs or outputs */
  return hi;
}

int hash_cache_append(HashCache *cache, SyscallConfig *config) {
  int err = 0;
  uint8_t temp[OPENTX_BATCH_SIZE];
  uint64_t len = OPENTX_BATCH_SIZE;
  uint64_t offset = 0;
  err = syscall(config->id, temp, &len, offset, config->index, config->source,
                config->field);
  // not panic when the field is missing, e.g. type script can be missing
  if (err == CKB_ITEM_MISSING) return 0;
  CHECK(err);
  offset = (len > OPENTX_BATCH_SIZE) ? OPENTX_BATCH_SIZE : len;
  blake2b_update(&cache->state, temp, offset);
  while (offset < len) {
    uint64_t current_len = OPENTX_BATCH_SIZE;
    err = syscall(config->id, temp, &current_len, offset, config->index,
                  config->source, config->field);
    CHECK(err);
    uint64_t current_read =
        (current_len > OPENTX_BATCH_SIZE) ? OPENTX_BATCH_SIZE : current_len;
    blake2b_update(&cache->state, temp, current_read);
    offset += current_read;
  }

exit:
  return 0;
}

void hash_cache_append2(HashCache *cache, uint8_t *buf, size_t len) {
  blake2b_update(&cache->state, buf, len);
}

int hash_cell_script(HashCache *cache, size_t index, size_t source,
                     size_t field, uint16_t cell_mask) {
  uint8_t script[OPENTX_SCRIPT_SIZE];
  uint64_t len = OPENTX_SCRIPT_SIZE;
  int err =
      ckb_checked_load_cell_by_field(script, &len, 0, index, source, field);
  if (err == CKB_ITEM_MISSING && field == CKB_CELL_FIELD_TYPE) {
    return 0;
  }
  CHECK(err);

  mol_seg_t script_seg;
  script_seg.ptr = script;
  script_seg.size = (mol_num_t)len;

  mol_errno mol_err = MolReader_Script_verify(&script_seg, false);
  CHECK2(mol_err == MOL_OK, OPENTX_ERROR_ENCODING);

  // lock\type.code_hash
  if ((cell_mask & 0x2 && field == CKB_CELL_FIELD_LOCK) ||
      (cell_mask & 0x10 && field == CKB_CELL_FIELD_TYPE)) {
    mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
    CHECK2(code_hash_seg.size == 32, OPENTX_ERROR_ENCODING);
    hash_cache_append2(cache, code_hash_seg.ptr, code_hash_seg.size);
  }
  // lock\type.hash_type
  if ((cell_mask & 0x4 && field == CKB_CELL_FIELD_LOCK) ||
      (cell_mask & 0x20 && field == CKB_CELL_FIELD_TYPE)) {
    mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);
    CHECK2(hash_type_seg.size == 1, OPENTX_ERROR_ENCODING);
    hash_cache_append2(cache, hash_type_seg.ptr, hash_type_seg.size);
  }
  // lock\type.args
  if ((cell_mask & 0x8 && field == CKB_CELL_FIELD_LOCK) ||
      (cell_mask & 0x40 && field == CKB_CELL_FIELD_TYPE)) {
    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t seg = MolReader_Bytes_raw_bytes(&args_seg);
    hash_cache_append2(cache, seg.ptr, seg.size);
  }

exit:
  return err;
}

// hash part or the whole cell, including input/output, index or offset
int hash_cell(HashCache *cache, bool is_input, bool with_offset,
              size_t base_index, SignatureInput *si) {
  int err = 0;
  size_t source = CKB_SOURCE_OUTPUT;
  if (is_input) {
    source = CKB_SOURCE_INPUT;
  }
  size_t index = si->arg1;
  if (with_offset) {
    index += base_index;
  }
  // capacity
  if (si->arg2 & 0x1) {
    SyscallConfig config = {
        .id = SYS_ckb_load_cell_by_field,
        .index = index,
        .source = source,
        .field = CKB_CELL_FIELD_CAPACITY,
    };
    err = hash_cache_append(cache, &config);
    CHECK(err);
  }
  // lock.code_hash
  // lock.hash_type
  // lock.args
  if (si->arg2 & (0x2 | 0x4 | 0x8)) {
    err = hash_cell_script(cache, index, source, CKB_CELL_FIELD_LOCK, si->arg2);
    CHECK(err);
  }

  // type.code_hash
  // type.hash_type
  // type.args
  if (si->arg2 & (0x10 | 0x20 | 0x40)) {
    err = hash_cell_script(cache, index, source, CKB_CELL_FIELD_TYPE, si->arg2);
    CHECK(err);
  }

  // cell data
  if (si->arg2 & 0x80) {
    SyscallConfig config = {
        .id = SYS_ckb_load_cell_data,
        .index = index,
        .source = source,
        .field = 0,
    };
    err = hash_cache_append(cache, &config);
    CHECK(err);
  }
  // lock script hash
  if (si->arg2 & 0x100) {
    SyscallConfig config = {
        .id = SYS_ckb_load_cell_by_field,
        .index = index,
        .source = source,
        .field = CKB_CELL_FIELD_LOCK_HASH,
    };
    err = hash_cache_append(cache, &config);
    CHECK(err);
  }
  // type script hash
  if (si->arg2 & 0x200) {
    SyscallConfig config = {
        .id = SYS_ckb_load_cell_by_field,
        .index = index,
        .source = source,
        .field = CKB_CELL_FIELD_TYPE_HASH,
    };
    err = hash_cache_append(cache, &config);
    CHECK(err);
  }
  // the whole cell
  if (si->arg2 & 0x400) {
    SyscallConfig config = {
        .id = SYS_ckb_load_cell,
        .index = index,
        .source = source,
        .field = 0,
    };
    err = hash_cache_append(cache, &config);
    CHECK(err);
  }

exit:
  return err;
}

// hash part or the whole cell input structure, including index or offset
int hash_input(HashCache *cache, bool with_offset, size_t base_index,
               SignatureInput *si) {
  int err = 0;
  size_t index = si->arg1;
  if (with_offset) {
    index += base_index;
  }
  // previous_output.tx_hash
  // previous_output.index
  if ((si->arg2 & 0x1) || (si->arg2 & 0x2)) {
    uint8_t input[MAX_INPUT_SIZE];
    uint64_t len = MAX_INPUT_SIZE;
    err = ckb_checked_load_input_by_field(
        input, &len, 0, index, CKB_SOURCE_INPUT, CKB_INPUT_FIELD_OUT_POINT);
    CHECK(err);

    mol_seg_t input_seg;
    input_seg.ptr = input;
    input_seg.size = (mol_num_t)len;
    err = MolReader_OutPoint_verify(&input_seg, false);
    CHECK2(err == MOL_OK, OPENTX_ERROR_ENCODING);

    if (si->arg2 & 0x1) {
      mol_seg_t tx_hash = MolReader_OutPoint_get_tx_hash(&input_seg);
      CHECK2(tx_hash.size == 32, OPENTX_ERROR_ENCODING);
      hash_cache_append2(cache, tx_hash.ptr, tx_hash.size);
    }
    if (si->arg2 & 0x2) {
      mol_seg_t index = MolReader_OutPoint_get_index(&input_seg);
      CHECK2(index.size == 4, OPENTX_ERROR_ENCODING);
      hash_cache_append2(cache, index.ptr, index.size);
    }
  }

  // since
  if (si->arg2 & 0x4) {
    SyscallConfig config = {
        .id = SYS_ckb_load_input_by_field,
        .index = index,
        .source = CKB_SOURCE_INPUT,
        .field = CKB_INPUT_FIELD_SINCE,
    };
    err = hash_cache_append(cache, &config);
    CHECK(err);
  }
  if (si->arg2 & 0x8) {
    SyscallConfig config = {
        .id = SYS_ckb_load_input_by_field,
        .index = index,
        .source = CKB_SOURCE_INPUT,
        .field = CKB_INPUT_FIELD_OUT_POINT,
    };
    err = hash_cache_append(cache, &config);
    CHECK(err);
  }
  if (si->arg2 & 0x10) {
    SyscallConfig config = {
        .id = SYS_ckb_load_input,
        .index = index,
        .source = CKB_SOURCE_INPUT,
        .field = 0,
    };
    err = hash_cache_append(cache, &config);
    CHECK(err);
  }
exit:
  return err;
}

void hash_concat(HashCache *cache, SignatureInput *si) {
  uint32_t value = si->arg1 & 0xFFF;
  value |= (si->arg2 & 0xFFF) << 12;
  hash_cache_append2(cache, (uint8_t *)&value, 3);
}

int opentx_parse_witness(uint8_t *buf, size_t len, OpenTxWitness *witness) {
  int err = 0;
  CHECK2(len >= 8, OPENTX_ERROR_ENCODING);
  uint32_t base_input_index;
  uint32_t base_output_index;
  memcpy(&base_input_index, buf, 4);
  memcpy(&base_output_index, buf + 4, 4);
  witness->base_input_index = base_input_index;
  witness->base_output_index = base_output_index;

  size_t offset = 8;
  size_t temp_count = 0;
  while (offset < len) {
    uint8_t *p = buf + offset;
    offset += 4;
    if (*p == OPENTX_TERMINAL_COMMAND) {
      break;
    }
    temp_count++;
    CHECK2(temp_count <= MAX_SIL_SIZE, OPENTX_ERROR_ENCODING);
  }

  witness->sil = buf + 8;
  witness->sil_len = offset - 8;
  CHECK2(witness->sil_len % 4 == 0, OPENTX_ERROR_ENCODING);
  CHECK2(witness->sil_len / 4 <= MAX_SIL_SIZE, OPENTX_ERROR_ENCODING);
  CHECK2(witness->sil_len > 0, OPENTX_ERROR_ENCODING);

  CHECK2(offset < len, OPENTX_ERROR_ENCODING);
  witness->real_sig = buf + offset;
  witness->real_sig_len = len - offset;
exit:
  return err;
}

int parse_si(uint8_t *buf, size_t len, SignatureInput *si) {
  int err = 0;
  CHECK2(len >= 4, OPENTX_ERROR_ENCODING);
  uint32_t data = 0;
  memcpy(&data, buf, 4);

  si->command = data & 0xFF;
  si->arg1 = (data >> 8) & 0xFFF;
  si->arg2 = (data >> 20) & 0xFFF;
exit:
  return err;
}

int process_si(HashCache *cache, SignatureInput *si, size_t base_input_index,
               size_t base_output_index) {
  int err = 0;

  switch (si->command) {
    case 0x00: {
      SyscallConfig config = {
          .id = SYS_ckb_load_tx_hash, .index = 0, .source = 0, .field = 0};
      err = hash_cache_append(cache, &config);
      CHECK(err);
      break;
    }
    case 0x01: {
      // Hash length of input & output cells in current script group
      uint64_t input_len = calculate_group_len(true);
      uint64_t output_len = calculate_group_len(false);
      hash_cache_append2(cache, (uint8_t *)&input_len, 8);
      hash_cache_append2(cache, (uint8_t *)&output_len, 8);
      break;
    }
    case 0x11:
      // Hash part or the whole output cell with index
      err = hash_cell(cache, false, false, 0, si);
      CHECK(err);
      break;
    case 0x12:
      // Hash part or the whole output cell with offset
      err = hash_cell(cache, false, true, base_output_index, si);
      CHECK(err);
      break;
    case 0x13:
      // Hash part or the whole input cell with index
      err = hash_cell(cache, true, false, 0, si);
      CHECK(err);
      break;
    case 0x14:
      // Hash part or the whole input cell with offset
      err = hash_cell(cache, true, true, base_input_index, si);
      CHECK(err);
      break;
    case 0x15:
      // Hash part or the whole cell input structure with index
      err = hash_input(cache, false, 0, si);
      CHECK(err);
      break;
    case 0x16:
      // Hash part or the whole cell input structure with offset
      err = hash_input(cache, true, base_input_index, si);
      CHECK(err);
      break;
    case 0x20:
      hash_concat(cache, si);
      break;
    default:
      err = OPENTX_ERROR_UNKNOWN_COMMAND;
      break;
  }
  CHECK(err);

exit:
  return err;
}

int opentx_generate_message(OpenTxWitness *witness, uint8_t *buf, size_t len,
                            uint8_t *msg, size_t msg_len) {
  int err = 0;

  CHECK2(msg_len == BLAKE2B_BLOCK_SIZE, OPENTX_ERROR_INVALID_ARGUMENT);
  HashCache cache = {0};
  err = hash_cache_init(&cache);
  CHECK(err);
  size_t si_count = witness->sil_len / 4;
  for (size_t i = 0; i < si_count; i++) {
    SignatureInput si = {0};
    err = parse_si(witness->sil + i * 4, witness->sil_len - i * 4, &si);
    CHECK(err);
    if (si.command == OPENTX_TERMINAL_COMMAND) {
      break;
    }
    err = process_si(&cache, &si, witness->base_input_index,
                     witness->base_output_index);
    CHECK(err);
  }
  // At last, the signature input list is also fed into blake2b instance
  hash_cache_append2(&cache, witness->sil, witness->sil_len);

  blake2b_final(&cache.state, msg, BLAKE2B_BLOCK_SIZE);
exit:
  return err;
}

#endif
