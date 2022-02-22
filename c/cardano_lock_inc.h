#include <string.h>
#include <stdint.h>

#include "nanocbor.h"

#ifndef ASSERT
#define ASSERT(s) (void)0
#endif

#define CHECK(f, rc_code) \
  {                       \
    bool flag = f;        \
    if (!flag) {          \
      ASSERT(false);      \
      ckb_exit(rc_code);  \
    }                     \
  }
// printf("check code is failed, %s:%d\n", __FILE__, __LINE__);

#define CHECK_RETURN(f, rc_code) \
  {                              \
    bool flag = f;               \
    if (!flag) {                 \
      ASSERT(false);             \
      return rc_code;            \
    }                            \
  }

#define CHECK_CARDANOCONVERT(f)     \
  {                                 \
    if (output && !(f)) {           \
      return ERROR_CONVERT_MESSAGE; \
    }                               \
  }

#define MAX_WITNESS_SIZE 32768
#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE2B_224_BLOCK_SIZE 28
#define ONE_BATCH_SIZE 32768
#define SCRIPT_SIZE 32768  // 32k

#define PUBLIC_KEY_SIZE 32
#define SIGNATURE_SIZE 64

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

int get_payload(const uint8_t *new_msg, size_t len, uint8_t *payload) {
  nanocbor_value_t n_val = {0};
  nanocbor_decoder_init(&n_val, new_msg, len);

  int val_type = nanocbor_get_type(&n_val);
  CHECK_RETURN(val_type == NANOCBOR_TYPE_ARR, ERROR_PAYLOAD);

  nanocbor_value_t n_array;
  int err = nanocbor_enter_array(&n_val, &n_array);
  CHECK_RETURN(err == NANOCBOR_OK, ERROR_PAYLOAD);

  uint8_t *tmp_buf = NULL;
  size_t tmp_len = 0;
  err = nanocbor_get_tstr(&n_array, (const uint8_t **)&tmp_buf, &tmp_len);
  CHECK_RETURN(err == NANOCBOR_OK, ERROR_PAYLOAD);
  const char *msg_sign_context = "Signature1";
  // msg_sign_context string size is 10
  CHECK_RETURN(tmp_len == 10, ERROR_PAYLOAD);
  CHECK_RETURN(memcmp(msg_sign_context, tmp_buf, tmp_len) == 0, ERROR_PAYLOAD);

  // null
  tmp_buf = NULL;
  tmp_len = 0;
  err = nanocbor_get_bstr(&n_array, (const uint8_t **)&tmp_buf, &tmp_len);
  CHECK_RETURN(err == NANOCBOR_OK, ERROR_PAYLOAD);

  // ext
  tmp_buf = NULL;
  tmp_len = 0;
  err = nanocbor_get_bstr(&n_array, (const uint8_t **)&tmp_buf, &tmp_len);
  CHECK_RETURN(err == NANOCBOR_OK, ERROR_PAYLOAD);

  // payload
  tmp_buf = NULL;
  tmp_len = 0;
  err = nanocbor_get_bstr(&n_array, (const uint8_t **)&tmp_buf, &tmp_len);
  CHECK_RETURN(err == NANOCBOR_OK, ERROR_PAYLOAD);
  CHECK_RETURN(tmp_len == BLAKE2B_BLOCK_SIZE, ERROR_PAYLOAD);
  memcpy(payload, tmp_buf, tmp_len);

  nanocbor_leave_container(&n_val, &n_array);

  return CKB_SUCCESS;
}
