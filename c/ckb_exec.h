#ifndef _CBK_C_STDLIB_CKB_EXEC_H_
#define _CBK_C_STDLIB_CKB_EXEC_H_
#include <stdint.h>
#include <string.h>

#ifndef CKB_EXEC_MAX_ARGS_COUNT
#define CKB_EXEC_MAX_ARGS_COUNT 64
#endif

#ifndef CKB_EXEC_MAX_BUFF_LEN
#define CKB_EXEC_MAX_BUFF_LEN (32 * 1024)
#endif

#ifndef CKB_EXEC_MAX_PARAM_LEN
#define CKB_EXEC_MAX_PARAM_LEN (32 * 1024)
#endif

enum CkbExecErrorCodeType {
  ERROR_EXEC_OUT_OF_BOUNDS = 30,
  ERROR_EXEC_INVALID_HEX,
};

typedef struct CkbBinaryArgsType {
  uint32_t count;
  uint32_t len[CKB_EXEC_MAX_ARGS_COUNT];
  uint8_t* params[CKB_EXEC_MAX_ARGS_COUNT];

  uint32_t used_buff;
  uint8_t buff[CKB_EXEC_MAX_BUFF_LEN];
} CkbBinaryArgsType;

typedef struct CkbHexArgsType {
  uint32_t used_buff;
  char buff[CKB_EXEC_MAX_BUFF_LEN];
} CkbHexArgsType;

static int _exec_getbin(uint8_t x, uint8_t* out) {
  if (x >= '0' && x <= '9') {
    *out = x - '0';
  } else if (x >= 'A' && x <= 'F') {
    *out = x - 'A' + 10;
  } else if (x >= 'a' && x <= 'f') {
    *out = x - 'a' + 10;
  } else {
    return ERROR_EXEC_INVALID_HEX;
  }
  return 0;
}

static void _exec_gethex(uint8_t x, char* out) {
  static char s_mapping[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                             '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  out[0] = s_mapping[(x >> 4) & 0x0F];
  out[1] = s_mapping[x & 0x0F];
}

int _exec_safe_strlen(const char* s, uint32_t limit, uint32_t* length) {
  if (s == NULL) return ERROR_EXEC_OUT_OF_BOUNDS;

  uint32_t count = 0;
  for (; *s; s++) {
    count++;
    if (count > limit) return ERROR_EXEC_OUT_OF_BOUNDS;
  }
  *length = count;
  return 0;
}

// the string length of "hex" should be no more than bin_len*2
// "length" returns the bytes count written in "bin"
static int _exec_hex2bin(const char* hex, uint8_t* bin, uint32_t bin_len,
                         uint32_t* length) {
  uint32_t limit = 2 * bin_len;
  uint32_t hex_len;
  int err = _exec_safe_strlen(hex, limit, &hex_len);
  if (err != 0) return err;
  if (hex_len % 2 != 0) return ERROR_EXEC_INVALID_HEX;
  *length = hex_len / 2;
  if (*length > bin_len) {
    return ERROR_EXEC_OUT_OF_BOUNDS;
  }
  for (uint32_t i = 0; i < *length; i++) {
    uint8_t high, low;
    err = _exec_getbin(hex[i * 2], &high);
    if (err != 0) return err;
    err = _exec_getbin(hex[i * 2 + 1], &low);
    if (err != 0) return err;
    bin[i] = high << 4 | low;
  }
  return 0;
}

static int _exec_bin2hex(const uint8_t* bin, uint32_t bin_len, char* hex,
                         uint32_t hex_len, uint32_t* length, bool last_field) {
  if (hex_len < (bin_len * 2 + 1)) {
    return ERROR_EXEC_OUT_OF_BOUNDS;
  }
  for (uint32_t i = 0; i < bin_len; i++) {
    _exec_gethex(bin[i], hex + 2 * i);
  }
  if (last_field)
    *(hex + bin_len * 2) = 0;
  else
    *(hex + bin_len * 2) = ':';

  *length = 2 * bin_len + 1;
  return 0;
}

// use ckb_exec_reset and ckb_exec_append to generate CkbBinaryArgsType from
// scratch
void ckb_exec_reset(CkbBinaryArgsType* args) {
  args->count = 0;
  args->used_buff = 0;
}

int ckb_exec_append(CkbBinaryArgsType* args, uint8_t* data, uint32_t len) {
  if (args->count >= CKB_EXEC_MAX_ARGS_COUNT) {
    return ERROR_EXEC_INVALID_HEX;
  }
  uint8_t* p = args->buff + args->used_buff;
  args->used_buff += len;
  if (args->used_buff > CKB_EXEC_MAX_BUFF_LEN) {
    return ERROR_EXEC_OUT_OF_BOUNDS;
  }

  memcpy(p, data, len);
  args->params[args->count] = p;
  args->len[args->count] = len;

  args->count++;

  return 0;
}

int ckb_exec_encode_params(CkbBinaryArgsType* in, CkbHexArgsType* out) {
  int err = 0;

  if (in->count > CKB_EXEC_MAX_ARGS_COUNT || in->count == 0) {
    return ERROR_EXEC_OUT_OF_BOUNDS;
  }

  out->used_buff = 0;

  for (uint32_t i = 0; i < in->count; i++) {
    uint8_t* p = in->params[i];
    uint32_t len = in->len[i];
    uint32_t length;
    if (out->used_buff >= CKB_EXEC_MAX_BUFF_LEN) {
      return ERROR_EXEC_OUT_OF_BOUNDS;
    }
    bool last_field = (i == (in->count - 1));
    err = _exec_bin2hex(p, len, out->buff + out->used_buff,
                        CKB_EXEC_MAX_BUFF_LEN - out->used_buff, &length,
                        last_field);
    if (err != 0) return err;
    out->used_buff += length;
  }
  return 0;
}

int ckb_exec_decode_params(char* argv, uint8_t** param_ptr, uint32_t* param_len,
                           char** next_iterator_argv) {
  int err = 0;
  *param_len = 0;
  *param_ptr = NULL;
  if (argv == NULL) {
    return ERROR_EXEC_INVALID_HEX;
  }
  uint8_t* cur = (uint8_t*)argv;
  uint8_t* write_ptr = cur;
  *param_ptr = cur;
  *param_len = 0;

  uint32_t count = 0;

  uint8_t high, low;
  while (true) {
    if (*cur == '\0') {
      *next_iterator_argv = NULL;
      break;
    }
    if (*cur == ':') {
      *next_iterator_argv = (char*)(cur + 1);
      break;
    }
    err = _exec_getbin(*cur, &high);
    if (err != 0) return err;
    cur++;
    err = _exec_getbin(*cur, &low);
    if (err != 0) return err;
    cur++;

    (*write_ptr) = high << 4 | low;
    write_ptr++;
    (*param_len)++;

    // prevent infinite loop when no ":" or "\0" is detected
    count++;
    if (count > CKB_EXEC_MAX_PARAM_LEN) {
      return ERROR_EXEC_OUT_OF_BOUNDS;
    }
  }
  return 0;
}

#endif  // _CBK_C_STDLIB_CKB_EXEC_H_

