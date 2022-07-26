#undef ASSERT
#include <assert.h>
#define ASSERT assert
#include <blake2b.h>

#include "include/secp256k1_schnorrsig.h"
#include "taproot_lock_mol.h"

#define VERY_LONG_DATA_SIZE 655360
#define SPECIAL_SECP256K1_INDEX 1111

#define countof(s) (sizeof(s) / sizeof(s[0]))
mol_seg_t build_bytes(const uint8_t* data, uint32_t len);
mol_seg_t build_script(const uint8_t* code_hash, uint8_t hash_type,
                       const uint8_t* args, uint32_t args_len);
int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset);
int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source);
int calculate_hash(uint8_t* msg);
void schnorr_sign(const uint8_t* sk, const uint8_t* msg,
                  uint8_t* serialized_sig, uint8_t* pubkey_hash);
void ckb_tagged_hash(const uint8_t* tag, size_t tag_len, const uint8_t* msg,
                     size_t msg_len, uint8_t* out);
typedef struct slice_t {
  uint8_t* ptr;
  uint32_t size;
} slice_t;

typedef struct {
  secp256k1_context* ctx;

  secp256k1_keypair keypair;
  secp256k1_xonly_pubkey internal_key;
  uint8_t internal_key_bytes[32];

  secp256k1_keypair tweaked_keypair;
  secp256k1_xonly_pubkey output_key;
  uint8_t output_key_bytes[32];

  uint8_t sig[64];
  uint8_t msg[32];
  int y_parity;

  uint8_t real_tweak32[32];
} taproot_context_t;

// set by users
typedef struct TaprootLockSettingType {
  uint8_t flags;  // identity's flags
  bool key_path_spending;
  uint8_t blake160[20];        // identity's blake160
  uint8_t signature[32 + 64];  // in witness

  bool script_path_spending;

  // test scheme
  bool wrong_signature;
  bool wrong_pubkey_hash;
  // owner lock without rc doesn't require witness
  bool empty_witness;
} TaprootLockSettingType;

typedef struct TaprootLockStates {
  TaprootLockSettingType setting;
  slice_t witness;
  slice_t script_path;
  slice_t script;
  slice_t cell_data[64];
  uint32_t cell_data_count;
  uint8_t seckey[32];
  taproot_context_t ctx;
} TaprootLockStates;

TaprootLockSettingType g_setting = {0};
TaprootLockStates g_states = {0};

slice_t new_slice(uint32_t size) {
  slice_t res = {.ptr = malloc(size), .size = size};
  memset(res.ptr, 0, size);
  return res;
}

slice_t copy_slice(uint8_t* ptr, uint32_t size) {
  slice_t s = new_slice(size);
  memcpy(s.ptr, ptr, size);
  return s;
}

void delete_slice(slice_t* t) {
  free(t->ptr);
  t->ptr = NULL;
  t->size = 0;
}

void init_input(void) {
  memset(&g_setting, 0, sizeof(TaprootLockSettingType));
  if (g_states.script.ptr) {
    free(g_states.script.ptr);
  }
  if (g_states.script_path.ptr) {
    free(g_states.script_path.ptr);
  }
  if (g_states.witness.ptr) {
    free(g_states.witness.ptr);
  }
  for (int i = 0; i < g_states.cell_data_count; i++) {
    if (g_states.cell_data[i].ptr) {
      free(g_states.cell_data[i].ptr);
    }
  }
  memset(&g_states, 0, sizeof(TaprootLockStates));
}

void taproot_init(taproot_context_t* tr_ctx, uint8_t* sk) {
  int ret = 0;
  tr_ctx->ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
                                         SECP256K1_CONTEXT_SIGN);

  ret = secp256k1_keypair_create(tr_ctx->ctx, &tr_ctx->keypair, sk);
  ASSERT(ret);

  ret = secp256k1_keypair_xonly_pub(tr_ctx->ctx, &tr_ctx->internal_key, NULL,
                                    &tr_ctx->keypair);
  ASSERT(ret);
  ret = secp256k1_xonly_pubkey_serialize(
      tr_ctx->ctx, tr_ctx->internal_key_bytes, &tr_ctx->internal_key);
  ASSERT(ret);
}

void taproot_sign(taproot_context_t* tr_ctx, uint8_t* tweak32) {
  int ret;

  uint8_t tagged_msg[64];
  secp256k1_xonly_pubkey_serialize(tr_ctx->ctx, tagged_msg,
                                   &tr_ctx->internal_key);
  memcpy(tagged_msg + 32, tweak32, 32);

  ckb_tagged_hash_tweak(tagged_msg, sizeof(tagged_msg), tr_ctx->real_tweak32);

  memcpy(&tr_ctx->tweaked_keypair, &tr_ctx->keypair, sizeof(secp256k1_keypair));
  ret = secp256k1_keypair_xonly_tweak_add(tr_ctx->ctx, &tr_ctx->tweaked_keypair,
                                          tr_ctx->real_tweak32);
  ASSERT(ret);

  ret =
      secp256k1_keypair_xonly_pub(tr_ctx->ctx, &tr_ctx->output_key,
                                  &tr_ctx->y_parity, &tr_ctx->tweaked_keypair);
  ASSERT(ret);

  ret = secp256k1_xonly_pubkey_serialize(tr_ctx->ctx, tr_ctx->output_key_bytes,
                                         &tr_ctx->output_key);
  ASSERT(ret);

  ret = secp256k1_schnorrsig_sign(tr_ctx->ctx, tr_ctx->sig, tr_ctx->msg,
                                  &tr_ctx->tweaked_keypair, NULL, NULL);
  ASSERT(ret);
}

mol_seg_t build_witness_lock() {
  mol_builder_t witness_lock;
  MolBuilder_TaprootLockWitnessLock_init(&witness_lock);

  if (g_setting.key_path_spending) {
    mol_seg_t signature =
        build_bytes(g_setting.signature, sizeof(g_setting.signature));

    MolBuilder_TaprootLockWitnessLock_set_signature(
        &witness_lock, signature.ptr, signature.size);
    free(signature.ptr);
  } else if (g_setting.script_path_spending) {
    MolBuilder_TaprootLockWitnessLock_set_script_path(
        &witness_lock, g_states.script_path.ptr, g_states.script_path.size);
  } else {
    ASSERT(false);
  }

  mol_seg_res_t res = MolBuilder_TaprootLockWitnessLock_build(witness_lock);
  ASSERT(res.errno == 0);
  return res.seg;
}

void convert_witness(void) {
  free(g_states.witness.ptr);
  // Witness
  mol_seg_t witness_lock = build_witness_lock();
  mol_seg_t witness_lock_bytes =
      build_bytes(witness_lock.ptr, witness_lock.size);

  mol_builder_t witness;
  MolBuilder_WitnessArgs_init(&witness);
  MolBuilder_WitnessArgs_set_lock(&witness, witness_lock_bytes.ptr,
                                  witness_lock_bytes.size);
  uint8_t random_data[VERY_LONG_DATA_SIZE] = {1};
  mol_seg_t witness_input_type = build_bytes(random_data, sizeof(random_data));
  MolBuilder_WitnessArgs_set_input_type(&witness, witness_input_type.ptr,
                                        witness_input_type.size);

  free(witness_input_type.ptr);
  free(witness_lock.ptr);
  free(witness_lock_bytes.ptr);

  mol_seg_res_t res = MolBuilder_WitnessArgs_build(witness);
  ASSERT(res.errno == 0);

  g_states.witness.ptr = res.seg.ptr;
  g_states.witness.size = res.seg.size;
}

int generate_sighash_all(uint8_t* msg, size_t msg_len);

uint8_t EXEC_ARGS[3] = {'4', '2', 0};
uint8_t EXEC_ARGS2[4] = {1, 2, 3, 4};

void convert_setting_to_states(void) {
  if (g_states.script_path.ptr) {
    free(g_states.script_path.ptr);
  }
  g_states.setting = g_setting;
  ASSERT(g_setting.flags == 0x7);

  for (size_t i = 0; i < 32; i++) {
    g_states.seckey[i] = (uint8_t)i;
  }

  if (g_setting.key_path_spending) {
    // make witness skeleton
    convert_witness();
    // sign
    uint8_t msg[32] = {0};
    uint8_t sig[32 + 64] = {0};
    uint8_t pubkey_hash[32] = {0};
    generate_sighash_all(msg, sizeof(msg));
    schnorr_sign(g_states.seckey, msg, sig, pubkey_hash);

    memcpy(g_setting.blake160, pubkey_hash, 20);
    if (g_setting.wrong_pubkey_hash) {
      g_setting.blake160[0] ^= 0x1;
    }
    memcpy(g_setting.signature, sig, 32 + 64);
    if (g_setting.wrong_signature) {
      g_setting.signature[0] ^= 0x1;
    }
    // make witness again, with correct signature
    convert_witness();

    // Script
    uint8_t script_args[1 + 20] = {0};

    script_args[0] = g_setting.flags;
    memcpy(script_args + 1, g_setting.blake160, 20);
    uint8_t code_hash[32] = {0};

    mol_seg_t script = build_script(code_hash, 0, script_args, 21);
    g_states.script.ptr = script.ptr;
    g_states.script.size = script.size;
  } else if (g_setting.script_path_spending) {
    taproot_init(&g_states.ctx, g_states.seckey);
    // prepare exec script
    uint8_t code_hash[32] = {0};
    uint8_t hash_type = 0;
    mol_seg_t exec_script =
        build_script(code_hash, hash_type, EXEC_ARGS, sizeof(EXEC_ARGS));
    uint8_t script_hash[32];
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, 32);
    blake2b_update(&blake2b_ctx, exec_script.ptr, exec_script.size);
    blake2b_final(&blake2b_ctx, script_hash, 32);

    mol_seg_t args2 = build_bytes(EXEC_ARGS2, sizeof(EXEC_ARGS2));

#if 0
    printf("key = 0x");
    for (int i = 0; i < 32; i++) {
      printf("%02X", script_hash[i]);
    }
    printf("\n");
#endif
    // smt-cli --include 0
    // 0x59C9F2161D167503EBA44CA35372198B6398121025AFAD3AECD44722353F16CA
    // script hash
    uint8_t root[] = {219, 55, 33,  9,   156, 203, 245, 127, 68,  128, 239,
                      250, 98, 7,   226, 6,   47,  50,  148, 227, 55,  236,
                      151, 81, 150, 191, 220, 174, 167, 108, 43,  227};
    uint8_t proof[] = {76, 79, 0};

    taproot_sign(&g_states.ctx, root);

    mol_builder_t script_path_builder;
    MolBuilder_TaprootScriptPath_init(&script_path_builder);

    MolBuilder_TaprootScriptPath_set_taproot_output_key(
        &script_path_builder, g_states.ctx.output_key_bytes, 32);
    MolBuilder_TaprootScriptPath_set_taproot_internal_key(
        &script_path_builder, g_states.ctx.internal_key_bytes, 32);
    MolBuilder_TaprootScriptPath_set_smt_root(&script_path_builder, root, 32);
    mol_seg_t proof_bytes = build_bytes(proof, sizeof(proof));
    MolBuilder_TaprootScriptPath_set_smt_proof(
        &script_path_builder, proof_bytes.ptr, proof_bytes.size);
    MolBuilder_TaprootScriptPath_set_y_parity(&script_path_builder,
                                              (uint8_t)g_states.ctx.y_parity);
    MolBuilder_TaprootScriptPath_set_exec_script(
        &script_path_builder, exec_script.ptr, exec_script.size);
    MolBuilder_TaprootScriptPath_set_args2(&script_path_builder, args2.ptr,
                                           args2.size);

    mol_seg_res_t res = MolBuilder_TaprootScriptPath_build(script_path_builder);
    ASSERT(res.errno == 0);

    g_states.script_path.ptr = res.seg.ptr;
    g_states.script_path.size = res.seg.size;

    free(exec_script.ptr);
    free(args2.ptr);
#if 0
    debug_print_hex("output_key_bytes = ", g_states.ctx.output_key_bytes, 4);
    printf("y_parity = %d\n", g_states.ctx.y_parity);
    debug_print_hex("internal_key_bytes = ", g_states.ctx.internal_key_bytes, 4);
    debug_print_hex("smt_root = ", root, 4);
#endif
    convert_witness();

    // Script
    ckb_blake160(g_states.ctx.output_key_bytes, 32, g_setting.blake160);
    uint8_t script_args[1 + 20] = {0};
    script_args[0] = g_setting.flags;
    memcpy(script_args + 1, g_setting.blake160, 20);

    if (g_setting.wrong_pubkey_hash) {
      script_args[1] ^= 1;
    }
    uint8_t code_hash2[32] = {0};

    mol_seg_t script2 = build_script(code_hash2, 0, script_args, 21);
    g_states.script.ptr = script2.ptr;
    g_states.script.size = script2.size;

  } else {
    ASSERT(false);
  }
}

void schnorr_sign(const uint8_t* sk, const uint8_t* msg, uint8_t* sig,
                  uint8_t* pubkey_hash) {
  int err = 0;
  secp256k1_xonly_pubkey pubkey;
  secp256k1_keypair keypair;
  uint8_t pubkey_bytes[32];

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  err = secp256k1_keypair_create(ctx, &keypair, sk);
  ASSERT(err);
  err = secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair);
  ASSERT(err);
  err = secp256k1_schnorrsig_sign(ctx, sig + 32, msg, &keypair, NULL, NULL);
  ASSERT(err);

  secp256k1_xonly_pubkey_serialize(ctx, pubkey_bytes, &pubkey);
  memcpy(sig, pubkey_bytes, 32);

  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, pubkey_bytes, 32);
  blake2b_final(&blake2b_ctx, pubkey_hash, 32);

#if 0
  printf("{");
  for (int i = 0; i < 20; i++) {
    printf("%d,", pubkey_hash[i]);
  }
  printf("}\n");
#endif
}

static int extract_witness_lock2(uint8_t* witness, uint64_t len,
                                 mol_seg_t* lock_bytes_seg) {
  if (len < 20) {
    return 1;
  }
  uint32_t lock_length = *((uint32_t*)(&witness[16]));
  if (len < 20 + lock_length) {
    return 1;
  } else {
    lock_bytes_seg->ptr = &witness[20];
    lock_bytes_seg->size = lock_length;
  }
  return 0;
}

// replaced by generate_sighash_all
int calculate_hash(uint8_t* msg) {
  int ret;
  uint64_t len = 0;
  unsigned char temp[VERY_LONG_DATA_SIZE + 1024];
  uint64_t witness_len = VERY_LONG_DATA_SIZE + 1024;
  /* Load witness of first input */
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  ASSERT(ret == 0);

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock2(temp, witness_len, &lock_bytes_seg);
  ASSERT(ret == 0);

  /* Load tx hash */
  unsigned char tx_hash[32];
  len = 32;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  ASSERT(ret == 0);
  /* Prepare sign message */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, tx_hash, 32);

  /* Clear lock field to zero, then digest the first witness */
  memset((void*)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char*)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, witness_len);

  blake2b_final(&blake2b_ctx, msg, 32);
  return 0;
}

int ckb_exit(int8_t code) {
  exit(code);
  return 0;
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  ASSERT(offset == 0);
  ASSERT(*len == 32);
  for (int i = 0; i < *len; i++) {
    ((uint8_t*)addr)[i] = 0;
  }
  return 0;
}

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source);

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source);

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source);

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) { return 0; }

int ckb_checked_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  uint64_t old_len = *len;
  int ret = ckb_load_script_hash(addr, len, offset);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  if (index > 0) {
    return CKB_INDEX_OUT_OF_BOUND;
  }

  if (g_setting.empty_witness) {
    *len = 0;
    return 0;
  }

  slice_t seg = g_states.witness;

  if (addr == NULL) {
    *len = seg.size;
    return 0;
  }
  if (seg.size <= offset) {
    *len = 0;
    return 0;
  }
  uint32_t remaining = seg.size - offset;
  if (remaining > *len) {
    memcpy(addr, seg.ptr + offset, *len);
  } else {
    memcpy(addr, seg.ptr + offset, remaining);
  }
  *len = remaining;

  return 0;
}

int ckb_checked_load_witness(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_witness(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

mol_seg_t build_bytes(const uint8_t* data, uint32_t len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Bytes_init(&b);
  for (uint32_t i = 0; i < len; i++) {
    MolBuilder_Bytes_push(&b, data[i]);
  }
  res = MolBuilder_Bytes_build(b);
  return res.seg;
}

mol_seg_t build_script(const uint8_t* code_hash, uint8_t hash_type,
                       const uint8_t* args, uint32_t args_len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Script_init(&b);

  MolBuilder_Script_set_code_hash(&b, code_hash, 32);
  MolBuilder_Script_set_hash_type(&b, hash_type);
  mol_seg_t bytes = build_bytes(args, args_len);
  MolBuilder_Script_set_args(&b, bytes.ptr, bytes.size);

  res = MolBuilder_Script_build(b);
  assert(res.errno == 0);
  assert(MolReader_Script_verify(&res.seg, false) == 0);
  free(bytes.ptr);
  return res.seg;
}

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset) {
  ASSERT(offset == 0);
  ASSERT(*len > g_states.script.size);

  memcpy(addr, g_states.script.ptr, g_states.script.size);
  *len = g_states.script.size;
  return 0;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  ASSERT(offset == 0);
  ASSERT(*len > g_states.script.size);

  memcpy(addr, g_states.script.ptr, g_states.script.size);
  *len = g_states.script.size;
  return 0;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field);

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field);

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
  return -1;
}

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source);

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  if (source == CKB_SOURCE_CELL_DEP && index == SPECIAL_SECP256K1_INDEX) {
    ASSERT(*len == 1048576);
    FILE* input = fopen("build/secp256k1_data_20210801", "rb");
    size_t read_item = fread(addr, *len, 1, input);
    ASSERT(read_item == 1);

    return 0;
  }

  if (source == CKB_SOURCE_CELL_DEP) {
    ASSERT(index < g_states.cell_data_count);
    slice_t* cur = g_states.cell_data + index;
    if (addr == NULL) {
      *len = cur->size;
      return 0;
    }
    if (cur->size <= offset) {
      *len = 0;
      return 0;
    }
    uint32_t remaining = cur->size - offset;
    if (remaining > *len) {
      memcpy(addr, cur->ptr + offset, *len);
    } else {
      memcpy(addr, cur->ptr + offset, remaining);
    }
    *len = remaining;
  }
  return 0;
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

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  if (field == CKB_CELL_FIELD_LOCK_HASH) {
    if (source == CKB_SOURCE_GROUP_OUTPUT || source == CKB_SOURCE_OUTPUT) {
      ASSERT(false);
    } else {
      ASSERT(false);
    }
  } else {
    if (source == CKB_SOURCE_CELL_DEP && field == CKB_CELL_FIELD_DATA_HASH) {
      if (index == SPECIAL_SECP256K1_INDEX) {
        static uint8_t ckb_secp256k1_data_hash[32] = {
            151, 153, 190, 226, 81,  185, 117, 184, 44, 69,  160,
            33,  84,  206, 40,  206, 200, 156, 88,  83, 236, 193,
            77,  18,  183, 184, 204, 207, 193, 158, 10, 244};
        memcpy(addr, ckb_secp256k1_data_hash, 32);
      } else {
        memset(addr, 0, 32);
      }
      return 0;
    } else {
      ASSERT(false);
    }
  }
  return 0;
}

int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell_by_field(addr, len, offset, index, source, field);
  if (ret == 0 && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index) {
  *index = *(uint16_t*)code_hash;
  return 0;
}

int ckb_exec_cell(const uint8_t* code_hash, uint8_t hash_type, uint32_t offset,
                  uint32_t length, int argc, const char* argv[]) {
  char argv1[1024];
  ckb_bin2hex(EXEC_ARGS, sizeof(EXEC_ARGS), argv1, sizeof(argv1));
  int equal = strcmp(argv1, argv[0]);
  if (equal != 0) {
    ASSERT(false);
    return 1;
  }
  char argv2[1024];
  ckb_bin2hex(EXEC_ARGS2, sizeof(EXEC_ARGS2), argv2, sizeof(argv2));
  equal = strcmp(argv2, argv[1]);
  if (equal != 0) {
    ASSERT(false);
    return 1;
  }
  return 0;
}

int ckb_dlopen2(const uint8_t* dep_cell_hash, uint8_t hash_type,
                uint8_t* aligned_addr, size_t aligned_size, void** handle,
                size_t* consumed_size) {
  return -1;
}
void* ckb_dlsym(void* handle, const char* symbol) { return 0; }

#undef ASSERT
#define ASSERT(s) (void)0
