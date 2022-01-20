// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <blake2b.h>

#include "ckb_consts.h"
#ifdef CKB_USE_SIM
#include "sim_ckb_syscalls.h"
#else  // CKB_USE_SIM
#include "ckb_syscalls.h"
#endif  // CKB_USE_SIM

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif


#include "molecule/molecule_reader.h"
#include "blockchain.h"
#include "blockchain-api2.h"

#include "ed25519.h"
#include "nanocbor.h"

#define MAX_WITNESS_SIZE 32768
#define BLAKE2B_BLOCK_SIZE 32
#define ONE_BATCH_SIZE 32768
#define CELL_DATA_SIZE 4086  // 4k
#define SCRIPT_SIZE 32768    // 32k

uint8_t g_mol_data_source[DEFAULT_DATA_SOURCE_LENGTH];

typedef enum _RET_ERROR {
  ERROR_IDENTITY_ARGUMENTS_LEN = 1,
  ERROR_IDENTITY_SYSCALL,
  ERROR_IDENTITY_ENCODING,
  ERROR_ENCODING,
  ERROR_GENERATE_NEW_MSG,
  ERROR_LOAD_SCRIPT,
  ERROR_LOAD_WITNESS,
  ERROR_VERIFY,
  ERROR_CHECK_PUBKEY,
} RET_ERROR;

int extract_witness_lock(uint8_t *witness, uint64_t len,
                         mol_seg_t *lock_bytes_seg) {
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t lock_seg = MolReader_WitnessArgs_get_lock(&witness_seg);

  if (MolReader_BytesOpt_is_none(&lock_seg)) {
    return ERROR_ENCODING;
  }
  *lock_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  return CKB_SUCCESS;
}

int load_and_hash_witness(blake2b_state *ctx, size_t start, size_t index,
                          size_t source, bool hash_length) {
  uint8_t temp[ONE_BATCH_SIZE];
  uint64_t len = ONE_BATCH_SIZE;
  int ret = ckb_load_witness(temp, &len, start, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (hash_length) {
    blake2b_update(ctx, (char *)&len, sizeof(uint64_t));
  }
  uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
  blake2b_update(ctx, temp, offset);
  while (offset < len) {
    uint64_t current_len = ONE_BATCH_SIZE;
    ret = ckb_load_witness(temp, &current_len, start + offset, index, source);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    uint64_t current_read =
        (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
    blake2b_update(ctx, temp, current_read);
    offset += current_read;
  }
  return CKB_SUCCESS;
}

int generate_sighash_all(uint8_t *msg, size_t msg_len) {
  int ret;
  uint64_t len = 0;
  unsigned char temp[MAX_WITNESS_SIZE];
  uint64_t read_len = MAX_WITNESS_SIZE;
  uint64_t witness_len = MAX_WITNESS_SIZE;

  if (msg_len < BLAKE2B_BLOCK_SIZE) {
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  }

  /* Load witness of first input */
  ret = ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_IDENTITY_SYSCALL;
  }
  witness_len = read_len;
  if (read_len > MAX_WITNESS_SIZE) {
    read_len = MAX_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, read_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_IDENTITY_ENCODING;
  }

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_IDENTITY_SYSCALL;
  }

  /* Prepare sign message */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness
   * lock_bytes_seg.ptr actually points to the memory in temp buffer
   * */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, read_len);

  // remaining of first witness
  if (read_len < witness_len) {
    ret = load_and_hash_witness(&blake2b_ctx, read_len, 0,
                                CKB_SOURCE_GROUP_INPUT, false);
    if (ret != CKB_SUCCESS) {
      return ERROR_IDENTITY_SYSCALL;
    }
  }

  // Digest same group witnesses
  size_t i = 1;
  while (1) {
    ret =
        load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_GROUP_INPUT, true);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_IDENTITY_SYSCALL;
    }
    i += 1;
  }

  // Digest witnesses that not covered by inputs
  i = (size_t)ckb_calculate_inputs_len();
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_INPUT, true);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_IDENTITY_SYSCALL;
    }
    i += 1;
  }

  blake2b_final(&blake2b_ctx, msg, BLAKE2B_BLOCK_SIZE);

  return 0;
}

size_t generate_new_msg(uint8_t *output, size_t output_len,
                        const uint8_t *payload, size_t payload_len,
                        const uint8_t *external_aad, size_t external_aad_len) {
  nanocbor_encoder_t enc;
  nanocbor_encoder_init(&enc, output, output_len);
  nanocbor_fmt_array(&enc, 4);

  const char *msg_sign_context = "Signature1";
  nanocbor_put_tstr(&enc, msg_sign_context);
  nanocbor_put_bstr(&enc, NULL, 0);
  nanocbor_put_bstr(&enc, external_aad, external_aad_len);
  nanocbor_put_bstr(&enc, payload, payload_len);

  return nanocbor_encoded_len(&enc);
}

static int _make_cursor(size_t index, size_t source, size_t len,
                        mol2_source_t read, mol2_cursor_t *cur) {
  ASSERT(cur);
  ASSERT(len);
  ASSERT(read);

  int err = 0;

  cur->offset = 0;
  cur->size = len;

  memset(g_mol_data_source, 0, sizeof(g_mol_data_source));
  mol2_data_source_t *ptr = (mol2_data_source_t *)g_mol_data_source;

  ptr->read = read;
  ptr->total_size = len;

  ptr->args[0] = index;
  ptr->args[1] = source;

  ptr->cache_size = 0;
  ptr->start_point = 0;
  ptr->max_cache_size = MAX_CACHE_SIZE;
  cur->data_source = ptr;

  return err;
}

static uint32_t _read_data_from_witness(uintptr_t arg[], uint8_t *ptr,
                                        uint32_t len, uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_witness(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

int _get_cursor_from_witness(WitnessArgsType *witness, size_t index,
                             size_t source) {
  int err = CKB_SUCCESS;
  mol2_cursor_t cur;
  uint64_t len = 0;
  ckb_load_witness(NULL, &len, 0, index, source);
  if (len == 0) {
    return ERROR_LOAD_WITNESS;
  }

  err = _make_cursor(index, source, len, _read_data_from_witness, &cur);
  if (err != CKB_SUCCESS) {
    return err;
  }

  *witness = make_WitnessArgs(&cur);
  return err;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main(int argc, const char *argv[]) {
#endif
  // Get public key
  uint8_t msg[32] = {0};
  int error = generate_sighash_all(msg, sizeof(msg));
  if (error != CKB_SUCCESS) {
    return error;
  }

  size_t new_msg_len = generate_new_msg(NULL, 0, msg, sizeof(msg), NULL, 0);
  if (new_msg_len == 0) {
    return ERROR_GENERATE_NEW_MSG;
  }
  uint8_t new_msg[new_msg_len];
  memset(new_msg, 0, new_msg_len);
  if (generate_new_msg(new_msg, new_msg_len, msg, sizeof(msg), NULL, 0)) {
    return ERROR_GENERATE_NEW_MSG;
  }

  // get lock args:
  uint8_t identity[21] = {0};

  unsigned char script[SCRIPT_SIZE];
  uint64_t scritp_len = SCRIPT_SIZE;
  error = ckb_load_script(script, &scritp_len, 0);
  if (error != CKB_SUCCESS || scritp_len > SCRIPT_SIZE) {
    return ERROR_LOAD_SCRIPT;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = scritp_len;

  mol_seg_t args = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_raw_bytes = MolReader_Bytes_raw_bytes(&args);
  if (args_raw_bytes.size < sizeof(identity)) {
    return ERROR_LOAD_SCRIPT;
  }
  memcpy(identity, args_raw_bytes.ptr, sizeof(identity));

  // uint8_t witness_data[96] = {0};
  // uint64_t witness_data_len = sizeof(witness_data);
  for (size_t index = 0;; index++) {
    WitnessArgsType witnesses;
    error = _get_cursor_from_witness(&witnesses, index, CKB_SOURCE_GROUP_INPUT);
    if (error == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (error != CKB_SUCCESS) {
      return ERROR_LOAD_WITNESS;
    }

    BytesOptType ot = witnesses.t->lock(&witnesses);
    mol2_cursor_t bytes = ot.t->unwrap(&ot);

    uint8_t witness_buff[96] = {0};
    if (mol2_read_at(&bytes, witness_buff, sizeof(witness_buff)) !=
        sizeof(witness_buff)) {
      return ERROR_LOAD_WITNESS;
    }

    uint8_t *pubkey = &witness_buff[0];
    uint8_t *signature = &witness_buff[32];

    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&blake2b_ctx, pubkey, BLAKE2B_BLOCK_SIZE);
    uint8_t pubkey_hash[32] = {0};
    blake2b_final(&blake2b_ctx, pubkey_hash, sizeof(pubkey_hash));
    if (memcmp(pubkey_hash, &identity[1], 20) != 0) {
      return ERROR_CHECK_PUBKEY;
    }

    int suc = ed25519_verify(signature, new_msg, new_msg_len, pubkey);
    if (suc != 1) {
      return ERROR_VERIFY;
    }
  }

  return 0;
}
