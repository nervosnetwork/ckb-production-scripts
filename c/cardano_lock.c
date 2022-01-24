// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF

#ifdef CKB_USE_SIM
#include "sim_ckb_syscalls.h"
#else  // CKB_USE_SIM
#include "ckb_syscalls.h"
#endif  // CKB_USE_SIM

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <blake2b.h>

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif

#include "molecule/molecule_reader.h"
#include "blockchain.h"
#include "blockchain-api2.h"

#include "ed25519.h"
#include "nanocbor.h"

#include "ckb_consts.h"

#define MAX_WITNESS_SIZE 32768
#define BLAKE2B_BLOCK_SIZE 32
#define ONE_BATCH_SIZE 32768
#define SCRIPT_SIZE 32768  // 32k

#define IDENTITY_SIZE 21
#define IDENTITY_HASH_SIZE 20
#define PUBLIC_KEY_SIZE 32
#define SIGNATURE_SIZE 64

typedef enum _RET_ERROR {
  ERROR_IDENTITY_ARGUMENTS_LEN = 1,
  ERROR_IDENTITY_SYSCALL,
  ERROR_IDENTITY_ENCODING,
  ERROR_ENCODING,
  ERROR_GENERATE_NEW_MSG,
  ERROR_LOAD_SCRIPT,
  ERROR_LOAD_WITNESS,
  ERROR_CONVERT_MESSAGE,
  ERROR_VERIFY,
  ERROR_CHECK_PUBKEY,
} RET_ERROR;

static int extract_witness_lock(uint8_t *witness, uint64_t len,
                                mol_seg_t *lock_bytes_seg) {
  if (len < 20) {
    return ERROR_IDENTITY_ENCODING;
  }
  uint32_t lock_length = *((uint32_t *)(&witness[16]));
  if (len < 20 + lock_length) {
    return ERROR_IDENTITY_ENCODING;
  } else {
    lock_bytes_seg->ptr = &witness[20];
    lock_bytes_seg->size = lock_length;
  }
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

#define CHECK(f, rc_code) \
  {                       \
    bool flag = f;        \
    if (!flag) {          \
      ASSERT(false);      \
      ckb_exit(rc_code);  \
    }                     \
  }

#define CHECK_CARDANOCONVERT(f)     \
  {                                 \
    if (output && !(f)) {           \
      return ERROR_CONVERT_MESSAGE; \
    }                               \
  }

int cardano_convert_copy(uint8_t *output, size_t *output_len,
                         const uint8_t *payload, size_t payload_len,
                         const uint8_t *external_aad, size_t external_aad_len) {
  nanocbor_encoder_t enc;
  nanocbor_encoder_init(&enc, output, *output_len);
  int err = nanocbor_fmt_array(&enc, 4);
  CHECK_CARDANOCONVERT(err > 0);

  const char *msg_sign_context = "Signature1";
  err = nanocbor_put_tstr(&enc, msg_sign_context);
  CHECK_CARDANOCONVERT(err == NANOCBOR_OK)

  err = nanocbor_put_bstr(&enc, NULL, 0);
  CHECK_CARDANOCONVERT(err == NANOCBOR_OK)

  err = nanocbor_put_bstr(&enc, external_aad, external_aad_len);
  CHECK_CARDANOCONVERT(err == NANOCBOR_OK)

  err = nanocbor_put_bstr(&enc, payload, payload_len);
  CHECK_CARDANOCONVERT(err == NANOCBOR_OK)

  *output_len = nanocbor_encoded_len(&enc);
  ASSERT(*output_len == 0);
  return CKB_SUCCESS;
}

int get_identity(uint8_t *identity) {
  int err = CKB_SUCCESS;
  unsigned char script[SCRIPT_SIZE];
  uint64_t script_len = SCRIPT_SIZE;
  err = ckb_load_script(script, &script_len, 0);
  CHECK(err == CKB_SUCCESS, err);
  CHECK(script_len <= SCRIPT_SIZE, ERROR_LOAD_SCRIPT);

  mol_seg_t script_seg = {(uint8_t *)script, script_len};

  mol_seg_t args = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_raw_bytes = MolReader_Bytes_raw_bytes(&args);
  CHECK(args_raw_bytes.size >= IDENTITY_SIZE, ERROR_LOAD_SCRIPT);
  memcpy(identity, args_raw_bytes.ptr, IDENTITY_SIZE);
  return CKB_SUCCESS;
}

int get_pubkey_and_signature(uint8_t *pubkey, uint8_t *signature) {
  int err = CKB_SUCCESS;
  uint8_t temp[MAX_WITNESS_SIZE] = {0};
  uint64_t temp_len = sizeof(temp);
  err = ckb_load_witness(temp, &temp_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  CHECK(err == CKB_SUCCESS, err);
  CHECK(temp_len <= sizeof(temp) && temp_len >= 20, ERROR_LOAD_WITNESS);

  mol_seg_t witness = {0};
  err = extract_witness_lock(temp, temp_len, &witness);
  CHECK(err == CKB_SUCCESS, err);

  // <ED25519 pubkey, 32 bytes><ED25519 signature, 64 bytes>
  CHECK(witness.size == PUBLIC_KEY_SIZE + SIGNATURE_SIZE, ERROR_LOAD_WITNESS);
  memcpy(pubkey, witness.ptr, PUBLIC_KEY_SIZE);
  memcpy(signature, &witness.ptr[PUBLIC_KEY_SIZE], SIGNATURE_SIZE);

  return CKB_SUCCESS;
}

int get_message(uint8_t *msg, size_t *msg_len) {
  uint8_t sighash_msg[BLAKE2B_BLOCK_SIZE] = {0};
  int err = generate_sighash_all(sighash_msg, sizeof(sighash_msg));
  CHECK(err == CKB_SUCCESS, err);

  size_t len = *msg_len;
  err = cardano_convert_copy(msg, &len, sighash_msg, sizeof(sighash_msg), NULL,
                             0);
  CHECK(*msg_len > len, ERROR_GENERATE_NEW_MSG)
  *msg_len = len;
  return CKB_SUCCESS;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main(int argc, const char *argv[]) {
#endif
  int err = CKB_SUCCESS;
  uint8_t identity[IDENTITY_SIZE] = {0};
  err = get_identity(identity);
  CHECK(err == CKB_SUCCESS, err);

  CHECK(identity[0] == 0x7, ERROR_LOAD_SCRIPT);

  // For the time being, only 48bytes will be generated
  uint8_t message[64] = {0};
  size_t message_len = sizeof(message);
  err = get_message(message, &message_len);
  CHECK(err == CKB_SUCCESS, err);

  uint8_t pubkey[PUBLIC_KEY_SIZE] = {0};
  uint8_t signature[SIGNATURE_SIZE] = {0};
  err = get_pubkey_and_signature(pubkey, signature);
  CHECK(err == CKB_SUCCESS, err);

  // check public key
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, pubkey, BLAKE2B_BLOCK_SIZE);
  uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
  blake2b_final(&blake2b_ctx, pubkey_hash, sizeof(pubkey_hash));
  CHECK(memcmp(pubkey_hash, &identity[1], IDENTITY_HASH_SIZE) == 0,
        ERROR_CHECK_PUBKEY);

  int suc = ed25519_verify(signature, message, message_len, pubkey);
  CHECK(suc == 1, ERROR_VERIFY);

  return 0;
}
