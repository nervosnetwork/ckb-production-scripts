#include "compact_udt_lock.h"

#ifdef CKB_USE_SIM
#include "simulator/ckb_syscall_cudt_sim.h"
#define CKBMAIN simulator_main
#else  // CKB_USE_SIM
#include "ckb_consts.h"
#include "ckb_syscalls.h"
#define CKBMAIN main
#endif  // CKB_USE_SIM

#include "blake2b.h"

#include "blockchain-api2.h"
#include "ckb_consts.h"
#include "ckb_smt.h"
#include "compact_udt_mol.h"
#include "compact_udt_mol2.h"
#include "xudt_rce_mol.h"
#include "xudt_rce_mol2.h"

#define SCRIPT_SIZE 32768    // 32k
#define CELL_DATA_SIZE 4086  // 4k

////////////////////////////////////////////////////////////////
// read mol data

uint8_t g_read_data_source[DEFAULT_DATA_SOURCE_LENGTH];

typedef CKBResCode (*func_get_data)(void* addr,
                                    uint64_t* len,
                                    size_t offset,
                                    size_t index,
                                    size_t source);

static uint32_t _read_from_cursor(uintptr_t arg[],
                                  uint8_t* ptr,
                                  uint32_t len,
                                  uint32_t offset) {
  CKBResCode err;
  uint64_t output_len = len;
  func_get_data func = (func_get_data)arg[0];
  err = func(ptr, &output_len, offset + arg[3], arg[1], arg[2]);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

static CKBResCode _make_cursor(int index,
                               int source,
                               int offset,
                               func_get_data func,
                               mol2_cursor_t* cur) {
  ASSERT_DBG(cur);

  CKBResCode err = 0;
  uint64_t len = 0;
  CHECK(func(NULL, &len, 0, index, source));

  CHECK2(len != 0, CKBERR_DATA_EMTPY);
  CHECK2(len <= sizeof(g_read_data_source), CKBERR_DATA_TOO_LONG);

  cur->offset = 0;
  cur->size = len;

  mol2_data_source_t* ptr = (mol2_data_source_t*)g_read_data_source;

  ptr->read = _read_from_cursor;
  ptr->total_size = len;

  ptr->args[0] = (uintptr_t)func;
  ptr->args[1] = index;
  ptr->args[2] = source;
  ptr->args[3] = offset;

  ptr->cache_size = 0;
  ptr->start_point = 0;
  ptr->max_cache_size = MAX_CACHE_SIZE;
  cur->data_source = ptr;

exit_func:
  return err;
}

static CKBResCode _get_cell_data_base(void* addr,
                                      uint64_t* len,
                                      size_t offset,
                                      size_t index,
                                      size_t source) {
  return ckb_load_cell_data(addr, len, offset, index, source);
}

static CKBResCode _get_witness_base(void* addr,
                                    uint64_t* len,
                                    size_t offset,
                                    size_t index,
                                    size_t source) {
  CKBResCode ret_code = ckb_load_witness(addr, len, offset, index, source);
  return ret_code;
}

#define ReadMemFromMol2(m, source, target, target_size)    \
  {                                                        \
    mol2_cursor_t tmp = m.t->source(&m);                   \
    memset((void*)target, 0, target_size);                 \
    uint32_t cudt_mol2_read_len =                          \
        mol2_read_at(&tmp, (uint8_t*)target, target_size); \
    if (cudt_mol2_read_len != target_size) {               \
      ASSERT_DBG(false);                                   \
      ckb_exit(CKBERR_UNKNOW);                             \
    }                                                      \
  }

#define ReadUint128FromMol2(m, source, target)               \
  {                                                          \
    mol2_cursor_t tmp = m.t->source(&m);                     \
    memset((void*)(&target), 0, sizeof(uint128_t));          \
    mol2_read_at(&tmp, (uint8_t*)(&target), sizeof(target)); \
  }

////////////////////////////////////////////////////////////////
// reader

int get_amount(size_t index, size_t source, uint128_t* amount) {
  uint64_t len = sizeof(uint128_t);
  return ckb_load_cell_data(amount, &len, 0, index, source);
}

CKBResCode _get_xudt_data(XudtDataType* data, size_t index, size_t source) {
  CKBResCode err = CKBERR_UNKNOW;
  mol2_cursor_t cur;
  err = _make_cursor(index, source, 4, _get_cell_data_base, &cur);
  CHECK2(err == CKBERR_DATA_EMTPY, CKBERR_CELLDATA_TOO_LOW);
  CHECK2(err == CKBERR_CELLDATA_INDEX_OUT_OF_BOUND,
         CKBERR_CELLDATA_INDEX_OUT_OF_BOUND);
  CHECK(err);

  *data = make_XudtData(&cur);

exit_func:
  return err;
}

CKBResCode get_cell_data(size_t index,
                         size_t source,
                         CellDataTypeScript* type,
                         uint128_t* amount,
                         Hash* hash) {
  CKBResCode err = CKBERR_UNKNOW;

  /*
  typedef struct _SUDTData {
    uint128_t amount;
    uint32_t flag;
    uint8_t smt_hash[32];
  } SUDTData;
  SUDTData data;
  */

  const uint32_t sudt_data_size =
      sizeof(uint128_t) + sizeof(uint32_t) + sizeof(Hash);
  uint8_t sudt_data[sudt_data_size];

  uint64_t data_len = sudt_data_size;
  int ret_err = ckb_load_cell_data(sudt_data, &data_len, 0, index, source);
  CHECK(ret_err);
  CHECK2(data_len > sizeof(uint128_t), CKBERR_CELLDATA_TOO_LOW);
  if (amount)
    *amount = *((uint128_t*)sudt_data);

  if (type == NULL && hash == NULL) {
    return CUDT_SUCCESS;
  }

  uint32_t flag = *(uint32_t*)(sudt_data + sizeof(uint128_t));
  if (data_len == sudt_data_size && flag == 0xFFFFFFFF) {
    if (hash)
      memcpy(hash, sudt_data + (sizeof(uint128_t) + sizeof(uint32_t)),
             sizeof(Hash));
    if (type)
      *type = TypeScript_sUDT;
    return CUDT_SUCCESS;
  }

  XudtDataType xudt_data;
  CHECK(_get_xudt_data(&xudt_data, index, source));
  mol2_cursor_t mol_lock_data = xudt_data.t->lock(&xudt_data);
  BytesType lock_data = make_Bytes(&mol_lock_data);
  uint32_t lock_data_size = lock_data.t->len(&lock_data);
  CHECK2(lock_data_size == 32, CKBERR_CELLDATA_UNKNOW);

  bool existing = false;
  if (hash) {
    uint8_t* tmp_hash = (uint8_t*)hash;
    for (uint32_t i = 0; i < lock_data_size; i++) {
      tmp_hash[i] = lock_data.t->get(&lock_data, i, &existing);
    }
  }
  if (type)
    *type = TypeScript_xUDT;
  return CUDT_SUCCESS;

exit_func:
  return err;
}

CKBResCode _get_cursor_from_witness(WitnessArgsType* witness,
                                    size_t index,
                                    size_t source) {
  CKBResCode err = 0;
  mol2_cursor_t cur;
  CHECK(_make_cursor(index, source, 0, _get_witness_base, &cur));

  *witness = make_WitnessArgs(&cur);

exit_func:
  return err;
}

CKBResCode get_cudt_witness(size_t index,
                            size_t source,
                            CompactUDTEntriesType* cudt_data) {
  int err = 0;
  WitnessArgsType witnesses;
  err = _get_cursor_from_witness(&witnesses, index, CKB_SOURCE_GROUP_INPUT);
  CHECK(err);

  BytesOptType ot = witnesses.t->input_type(&witnesses);
  mol2_cursor_t bytes = ot.t->unwrap(&ot);
  *cudt_data = make_CompactUDTEntries(&bytes);

exit_func:
  return err;
}

CKBResCode get_args(TypeID* type_id, Identity* identity, bool* has_id) {
  CKBResCode err = CUDT_SUCCESS;

  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return CUDTERR_LOAD_SCRIPT;
  }
  if (len > SCRIPT_SIZE) {
    return CUDTERR_LOAD_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t*)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return CUDTERR_LOAD_SCRIPT_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

  const int args_size = 1 + sizeof(TypeID);
  const int args_size_with_id = 1 + sizeof(TypeID) + sizeof(Identity);

  CHECK2((args_bytes_seg.ptr[0] == 0), CUDTERR_INVALID_VERSION);
  *type_id = *(TypeID*)(args_bytes_seg.ptr + 1);

  if (args_bytes_seg.size == args_size) {
    *has_id = false;
  } else if (args_bytes_seg.size == args_size_with_id) {
    *has_id = true;
    *identity = *(Identity*)(args_bytes_seg.ptr + args_size);
  } else {
    CHECK(CUDTERR_ARGS_SIZE_INVALID);
  }
exit_func:
  return err;
}
