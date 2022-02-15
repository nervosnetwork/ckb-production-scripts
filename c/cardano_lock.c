// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF

#ifdef CKB_USE_SIM
#include "sim_ckb_syscalls.h"
#else  // CKB_USE_SIM
#include "ckb_syscalls.h"
#endif  // CKB_USE_SIM

#include <blake2b.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif

#include "blockchain-api2.h"
#include "blockchain.h"
#include "cardano_lock_mol.h"
#include "cardano_lock_mol2.h"
#include "molecule/molecule_reader.h"

#include "ed25519.h"
#include "nanocbor.h"

#include "ckb_consts.h"

#define MAX_WITNESS_SIZE 32768
#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE2B_224_BLOCK_SIZE 28
#define ONE_BATCH_SIZE 32768
#define SCRIPT_SIZE 32768  // 32k

#define PUBLIC_KEY_SIZE 32
#define SIGNATURE_SIZE 64

uint8_t g_mol_data_source[DEFAULT_DATA_SOURCE_LENGTH];

typedef enum _RET_ERROR {
  ERROR_AUTH_ARGUMENTS_LEN = 1,
  ERROR_AUTH_SYSCALL,
  ERROR_AUTH_ENCODING,
  ERROR_ENCODING,
  ERROR_GENERATE_NEW_MSG,
  ERROR_LOAD_SCRIPT,
  ERROR_LOAD_WITNESS,
  ERROR_UNSUPPORTED_ARGS,
  ERROR_ARGS_LENGTH,
  ERROR_CONVERT_MESSAGE,
  ERROR_PAYLOAD,
  ERROR_VERIFY,
  ERROR_PUBKEY,
} RET_ERROR;

static int extract_witness_lock(uint8_t* witness,
                                uint64_t len,
                                mol_seg_t* lock_bytes_seg) {
  if (len < 20) {
    return ERROR_AUTH_ENCODING;
  }
  uint32_t lock_length = *((uint32_t*)(&witness[16]));
  if (len < 20 + lock_length) {
    return ERROR_AUTH_ENCODING;
  } else {
    lock_bytes_seg->ptr = &witness[20];
    lock_bytes_seg->size = lock_length;
  }
  return CKB_SUCCESS;
}

int load_and_hash_witness(blake2b_state* ctx,
                          size_t start,
                          size_t index,
                          size_t source,
                          bool hash_length) {
  uint8_t temp[ONE_BATCH_SIZE] = {0};
  uint64_t len = ONE_BATCH_SIZE;
  int ret = ckb_load_witness(temp, &len, start, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (hash_length) {
    blake2b_update(ctx, (char*)&len, sizeof(uint64_t));
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

int generate_sighash_all(uint8_t* msg, size_t msg_len) {
  int ret;
  uint64_t len = 0;
  unsigned char temp[MAX_WITNESS_SIZE] = {0};
  uint64_t read_len = MAX_WITNESS_SIZE;
  uint64_t witness_len = MAX_WITNESS_SIZE;

  if (msg_len < BLAKE2B_BLOCK_SIZE) {
    return ERROR_AUTH_ARGUMENTS_LEN;
  }

  /* Load witness of first input */
  ret = ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_AUTH_SYSCALL;
  }
  witness_len = read_len;
  if (read_len > MAX_WITNESS_SIZE) {
    read_len = MAX_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, read_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_AUTH_ENCODING;
  }

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE] = {0};
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_AUTH_SYSCALL;
  }

  /* Prepare sign message */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness
   * lock_bytes_seg.ptr actually points to the memory in temp buffer
   * */
  memset((void*)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char*)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, read_len);

  // remaining of first witness
  if (read_len < witness_len) {
    ret = load_and_hash_witness(&blake2b_ctx, read_len, 0,
                                CKB_SOURCE_GROUP_INPUT, false);
    if (ret != CKB_SUCCESS) {
      return ERROR_AUTH_SYSCALL;
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
      return ERROR_AUTH_SYSCALL;
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
      return ERROR_AUTH_SYSCALL;
    }
    i += 1;
  }

  blake2b_final(&blake2b_ctx, msg, BLAKE2B_BLOCK_SIZE);

  return 0;
}

#define CHECK(f, rc_code) \
  {                       \
    bool flag = f;        \
    if (!flag) {          \
      ASSERT(false);      \
      ckb_exit(rc_code);  \
    }                     \
  }
// printf("check code is failed, %s:%d\n", __FILE__, __LINE__);

#define CHECK_CARDANOCONVERT(f)     \
  {                                 \
    if (output && !(f)) {           \
      return ERROR_CONVERT_MESSAGE; \
    }                               \
  }

int cardano_convert_copy(uint8_t* output,
                         size_t* output_len,
                         const uint8_t* payload,
                         size_t payload_len,
                         const uint8_t* external_aad,
                         size_t external_aad_len) {
  nanocbor_encoder_t enc;
  nanocbor_encoder_init(&enc, output, *output_len);
  int err = nanocbor_fmt_array(&enc, 4);
  CHECK_CARDANOCONVERT(err > 0);

  const char* msg_sign_context = "Signature1";
  err = nanocbor_put_tstr(&enc, msg_sign_context);
  CHECK_CARDANOCONVERT(err == NANOCBOR_OK)

  err = nanocbor_put_bstr(&enc, NULL, 0);
  CHECK_CARDANOCONVERT(err == NANOCBOR_OK)

  err = nanocbor_put_bstr(&enc, external_aad, external_aad_len);
  CHECK_CARDANOCONVERT(err == NANOCBOR_OK)

  err = nanocbor_put_bstr(&enc, payload, payload_len);
  CHECK_CARDANOCONVERT(err == NANOCBOR_OK)

  *output_len = nanocbor_encoded_len(&enc);
  CHECK(output_len != 0, ERROR_CONVERT_MESSAGE);
  return CKB_SUCCESS;
}

int get_args(uint8_t* header, uint8_t* payment_pubkey, size_t* args_len) {
  int err = CKB_SUCCESS;
  unsigned char script[SCRIPT_SIZE] = {0};
  uint64_t script_len = SCRIPT_SIZE;
  err = ckb_load_script(script, &script_len, 0);
  CHECK(err == CKB_SUCCESS, err);
  CHECK(script_len <= SCRIPT_SIZE, ERROR_LOAD_SCRIPT);

  mol_seg_t script_seg = {(uint8_t*)script, script_len};

  mol_seg_t args = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_raw_bytes = MolReader_Bytes_raw_bytes(&args);
  CHECK(args_raw_bytes.size >= 1 + BLAKE2B_224_BLOCK_SIZE, ERROR_LOAD_SCRIPT);

  *header = args_raw_bytes.ptr[0];
  memcpy(payment_pubkey, &args_raw_bytes.ptr[1], BLAKE2B_BLOCK_SIZE);
  *args_len = args_raw_bytes.size;
  return CKB_SUCCESS;
}

static uint32_t _read_data_from_witness(uintptr_t arg[],
                                        uint8_t* ptr,
                                        uint32_t len,
                                        uint32_t offset) {
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

static int _make_cursor(size_t index,
                        size_t source,
                        size_t len,
                        mol2_source_t read,
                        mol2_cursor_t* cur) {
  int err = CKB_SUCCESS;

  cur->offset = 0;
  cur->size = len;

  memset(g_mol_data_source, 0, sizeof(g_mol_data_source));
  mol2_data_source_t* ptr = (mol2_data_source_t*)g_mol_data_source;

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

int _get_cursor_from_witness(WitnessArgsType* witness,
                             size_t index,
                             size_t source) {
  int err = 0;
  mol2_cursor_t cur;
  uint64_t len = 0;
  err = ckb_load_witness(NULL, &len, 0, index, source);
  CHECK(err == CKB_SUCCESS, err);
  CHECK(len != 0, ERROR_LOAD_WITNESS);

  err = _make_cursor(index, source, len, _read_data_from_witness, &cur);
  CHECK(err == CKB_SUCCESS, err);

  *witness = make_WitnessArgs(&cur);

  return err;
}

int get_witness_data(uint8_t* pubkey,
                     uint8_t* signature,
                     mol2_cursor_t* new_message) {
  int err = CKB_SUCCESS;
  WitnessArgsType witnesses;
  err = _get_cursor_from_witness(&witnesses, 0, CKB_SOURCE_GROUP_INPUT);
  CHECK(err == CKB_SUCCESS, err);

  BytesOptType ot = witnesses.t->lock(&witnesses);
  mol2_cursor_t bytes = ot.t->unwrap(&ot);
  CardanoWitnessLockType witness = make_CardanoWitnessLock(&bytes);

  mol2_cursor_t pubkey_cursor = witness.t->pubkey(&witness);
  uint32_t len = mol2_read_at(&pubkey_cursor, pubkey, PUBLIC_KEY_SIZE);
  CHECK(len == PUBLIC_KEY_SIZE, ERROR_LOAD_SCRIPT);

  mol2_cursor_t signature_cursor = witness.t->signature(&witness);
  len = mol2_read_at(&signature_cursor, signature, SIGNATURE_SIZE);
  CHECK(len == SIGNATURE_SIZE, ERROR_LOAD_SCRIPT);

  *new_message = witness.t->new_message(&witness);
  return CKB_SUCCESS;
}

// Here use blake2b without personal
int _blake2b_init_cardano(blake2b_state *S, size_t outlen) {
  blake2b_param P[1];

  if ((!outlen) || (outlen > BLAKE2B_OUTBYTES)) return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length = 0;
  P->fanout = 1;
  P->depth = 1;
  store32(&P->leaf_length, 0);
  store32(&P->node_offset, 0);
  store32(&P->xof_length, 0);
  P->node_depth = 0;
  P->inner_length = 0;
  memset(P->reserved, 0, sizeof(P->reserved));
  memset(P->salt, 0, sizeof(P->salt));
  memset(P->personal, 0, sizeof(P->personal));
  return blake2b_init_param(S, P);
}

void get_pubkey_hash(uint8_t* pubkey, uint8_t* hash) {
  blake2b_state blake2b_ctx;
  _blake2b_init_cardano(&blake2b_ctx, BLAKE2B_224_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, pubkey, PUBLIC_KEY_SIZE);
  blake2b_final(&blake2b_ctx, hash, BLAKE2B_224_BLOCK_SIZE);
}

int get_payload(const uint8_t* new_msg, size_t len, uint8_t* payload) {
  nanocbor_value_t n_val = {0};
  nanocbor_decoder_init(&n_val, new_msg, len);

  int val_type = nanocbor_get_type(&n_val);
  CHECK(val_type == NANOCBOR_TYPE_ARR, ERROR_PAYLOAD);

  nanocbor_value_t n_array;
  int err = nanocbor_enter_array(&n_val, &n_array);
  CHECK(err == NANOCBOR_OK, ERROR_PAYLOAD);

  uint8_t* tmp_buf = NULL;
  size_t tmp_len = 0;
  err = nanocbor_get_tstr(&n_array, (const uint8_t**)&tmp_buf, &tmp_len);
  CHECK(err == NANOCBOR_OK, ERROR_PAYLOAD);
  const char* msg_sign_context = "Signature1";
  // msg_sign_context string size is 10
  CHECK(tmp_len == 10, ERROR_PAYLOAD);
  CHECK(memcmp(msg_sign_context, tmp_buf, tmp_len) == 0, ERROR_PAYLOAD);

  // null
  tmp_buf = NULL;
  tmp_len = 0;
  err = nanocbor_get_bstr(&n_array, (const uint8_t**)&tmp_buf, &tmp_len);
  CHECK(err == NANOCBOR_OK, ERROR_PAYLOAD);

  // ext
  tmp_buf = NULL;
  tmp_len = 0;
  err = nanocbor_get_bstr(&n_array, (const uint8_t**)&tmp_buf, &tmp_len);
  CHECK(err == NANOCBOR_OK, ERROR_PAYLOAD);

  // payload
  tmp_buf = NULL;
  tmp_len = 0;
  err = nanocbor_get_bstr(&n_array, (const uint8_t**)&tmp_buf, &tmp_len);
  CHECK(err == NANOCBOR_OK, ERROR_PAYLOAD);
  CHECK(tmp_len == BLAKE2B_BLOCK_SIZE, ERROR_PAYLOAD);
  memcpy(payload, tmp_buf, tmp_len);

  nanocbor_leave_container(&n_val, &n_array);

  return CKB_SUCCESS;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main(int argc, const char* argv[]) {
#endif

  int err = CKB_SUCCESS;
  uint8_t header_type = 0;
  uint8_t payment_pubkey[BLAKE2B_224_BLOCK_SIZE] = {0};
  size_t args_len = 0;
  err = get_args(&header_type, payment_pubkey, &args_len);
  CHECK(err == CKB_SUCCESS, err);

  header_type = header_type >> 4;
  CHECK((header_type == 0b0000 || header_type == 0b0010 ||
         header_type == 0b0100 || header_type == 0b0110),
        ERROR_UNSUPPORTED_ARGS);

  if ((header_type == 0b0000 || header_type == 0b0010)) {
    CHECK(args_len >= 57, ERROR_ARGS_LENGTH);
  }

  if (header_type == 0b0110) {
    CHECK(args_len >= 29, ERROR_ARGS_LENGTH);
  }

  uint8_t pub_key[PUBLIC_KEY_SIZE] = {0};
  uint8_t signature[SIGNATURE_SIZE] = {0};
  mol2_cursor_t new_message_cursor;
  err = get_witness_data(pub_key, signature, &new_message_cursor);
  CHECK(err == CKB_SUCCESS, err);
  CHECK(new_message_cursor.size <= 65536, ERROR_LOAD_WITNESS);
  uint8_t new_message[new_message_cursor.size];
  CHECK(mol2_read_at(&new_message_cursor, new_message, sizeof(new_message)) ==
            sizeof(new_message),
        ERROR_LOAD_SCRIPT);

  uint8_t pubkey_hash[BLAKE2B_224_BLOCK_SIZE] = {0};
  get_pubkey_hash(pub_key, pubkey_hash);
  CHECK(memcmp(pubkey_hash, payment_pubkey, BLAKE2B_224_BLOCK_SIZE) == 0,
        ERROR_PUBKEY);

  // Get payload
  uint8_t payload[BLAKE2B_BLOCK_SIZE] = {0};
  err = get_payload(new_message, new_message_cursor.size, payload);
  CHECK(err == CKB_SUCCESS, err);

  uint8_t message[BLAKE2B_BLOCK_SIZE] = {0};
  err = generate_sighash_all(message, sizeof(message));
  CHECK(err == CKB_SUCCESS, err);
  CHECK(memcmp(payload, message, BLAKE2B_BLOCK_SIZE) == 0, ERROR_PAYLOAD);

  int suc =
      ed25519_verify(signature, new_message, new_message_cursor.size, pub_key);
  CHECK(suc == 1, ERROR_VERIFY);

  return 0;
}
