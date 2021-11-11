#ifndef _C_COMPACT_UDE_LOCK_H_
#define _C_COMPACT_UDE_LOCK_H_

#include <stdint.h>

// check
#undef CHECK2
#undef CHECK

#ifdef ENABLE_DEBUG
#define PRINT_CHECK_ERR() \
  printf("Check error(%d): %s:%d\n", err, __FILE__, __LINE__)
#else  // ENABLE_DEBUG
#define PRINT_CHECK_ERR()
#endif  // ENABLE_DEBUG

#define CUDT_CHECK2(cond, code) \
  do {                          \
    if (!(cond)) {              \
      err = code;               \
      ASSERT_DBG(0);            \
      PRINT_CHECK_ERR();        \
      goto exit_func;           \
    }                           \
  } while (0)

#define CUDT_CHECK(_code) \
  do {                    \
    int code = (_code);   \
    if (code != 0) {      \
      err = code;         \
      ASSERT_DBG(0);      \
      PRINT_CHECK_ERR();  \
      goto exit_func;     \
    }                     \
  } while (0)

#ifdef CKB_USE_SIM
#undef ASSERT_DBG
#include <assert.h>
#ifdef ENABLE_DEBUG
#define ASSERT_DBG(i) \
  if (!(i)) {         \
    assert(false);    \
    int* a = NULL;    \
    *a = 0;           \
  }
#else  // ENABLE_DEBUG
#define ASSERT_DBG(i) \
  if (!(i)) {         \
  }
#endif  // ENABLE_DEBUG

#else  // CKB_USE_SIM
#ifdef ENABLE_DEBUG
#define ASSERT_DBG(i)                                         \
  if (!(i)) {                                                 \
    printf("assert failed(%d): %s:%d\n", __FILE__, __LINE__); \
  }
#else  // ENABLE_DEBUG
#define ASSERT_DBG(i)
#endif  // ENABLE_DEBUG
#endif  // CKB_USE_SIM

#define ADD_AND_CHECK_OVERFOLW(a, b, res) \
  if (a + b < a) {                        \
    ASSERT_DBG(false);                    \
    CUDT_CHECK(CUDTERR_AMOUNT_OVERFLOW);  \
  }                                       \
  res = a + b;

#define ADD_SELF_AND_CHECK_OVERFOLW(res, a) \
  res += a;                                 \
  if (res < a) {                            \
    ASSERT_DBG(false);                      \
    CUDT_CHECK(CUDTERR_AMOUNT_OVERFLOW);    \
  }

// mol
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif

#ifndef uint128_t
typedef __uint128_t uint128_t;
#endif  // uint128_t

#define MAX_WITNESS_SIZE 32768
#define BLAKE2B_BLOCK_SIZE 32
#define ONE_BATCH_SIZE 32768

enum _CompactResult {
  CUDT_SUCCESS = 0,

  CUDTERR_LOAD_SCRIPT = 1,
  CUDTERR_LOAD_SCRIPT_TOO_LONG,
  CUDTERR_LOAD_SCRIPT_ENCODING,
  CUDTERR_ARGS_SIZE_INVALID,
  CUDTERR_ARGS_UNKNOW,

  CUDTERR_LOAD_INPUT_CELL_DATA = 6,
  CUDTERR_LOAD_OUTPUT_CELL_DATA,
  CUDTERR_LOAD_UDT_INVALID,
  CUDTERR_CELL_NOT_ONLY,
  CDUTERR_CELL_DATA_TOO_LOW,
  CUDTERR_LOAD_SCRIPT_HASH,
  CUDTERR_INVALID_VERSION,

  CUDTERR_LOAD_OTHER_DATA = 13,

  CUDTERR_WITNESS_INVALID = 14,
  CUDTERR_WITNESS_OTHER_INVALID,
  CUDTERR_CHECK_IDENTITY_INVALID,

  CUDTERR_KV_TOO_LONG = 17,
  CUDTERR_KV_VERIFY,

  CUDTERR_SMTPROOF_SIZE_INVALID,

  CUDTERR_NO_ENOUGH_UDT,
  CUDTERR_OTHER_NO_ENOUGH_UDT,
  CUDTERR_OTHER_AMOUNT_INVALID,

  CUDTERR_DEPOSIT_INVALID,
  CUDTERR_DEPOSIT_NO_KVPAIR,

  CUDTERR_TRANSFER_INVALID,
  CUDTERR_TRANSFER_NO_KVPAIR,
  CUDTERR_TRANSFER_ENOUGH_UDT,
  CUDTERR_TRANSFER_SIGN_INVALID,
  CUDTERR_TRANSFER_SRC_NO_KV_PAIR,

  CUDTERR_AMOUNT_OVERFLOW,
  CUDTERR_NONCE_OVERFLOW,

  // Old, will remove

  CKBERR_CELLDATA_TOO_LOW,
  CKBERR_CELLDATA_INDEX_OUT_OF_BOUND,
  CKBERR_CELLDATA_UNKNOW,

  CKBERR_DATA_EMTPY,
  CKBERR_DATA_TOO_LONG,

  CKBERR_UNKNOW = 255,
};
typedef uint8_t ckb_res_code;

enum _CellDataTypeScript {
  Unknow = 0,
  TypeScript_sUDT,
  TypeScript_xUDT,
};
typedef uint8_t CellDataTypeScript;

#define CUDT_HASH_SIZE 32
typedef struct _Hash {
  uint8_t hash[CUDT_HASH_SIZE];
} Hash;
#undef CUDT_HASH_SIZE

#define CUDT_IDENTITY 21
typedef struct _Identity {
  uint8_t identity[CUDT_IDENTITY];
} Identity;
#undef CUDT_IDENTITY

#define CUDT_TYPE_ID 32
typedef struct _TypeID {
  uint8_t type_id[CUDT_TYPE_ID];
} TypeID;
#undef CUDT_TYPE_ID

enum _CacheTransferTargetType {
  TargetType_ScriptHash = 0,
  TargetType_Identity,
  TargetType_MoveBetweenCompactSMT,
};
typedef uint8_t CacheTransferSourceType;

typedef struct _CKBCellData {
  CellDataTypeScript type;  // type script type
  uint128_t amount;
  uint8_t smt_root_hash[32];
} CKBCellData;

#endif  // _C_COMPACT_UDE_LOCK_H_
