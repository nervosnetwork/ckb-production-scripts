#if defined(CKB_COVERAGE)
#define ASSERT(s) (void)0
#else
#define ASSERT(s) (void)0
#endif

int ckb_exit(signed char code);

#include "utest.h"
#include "xudt_rce.c"
void debug_print_hex(const char* prefix, const uint8_t* buf, size_t length) {
  printf("%s: ", prefix);
  for (size_t i = 0; i < length; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

/* hex2bin modified from
 * https://chromium.googlesource.com/chromium/deps/xz/+/77022065014d48cf51d83322264ab4836fd175ec/debug/hex2bin.c
 */
int getbin(int x) {
  if (x >= '0' && x <= '9') return x - '0';
  if (x >= 'A' && x <= 'F') return x - 'A' + 10;
  return x - 'a' + 10;
}

int hex2bin(uint8_t* buf, const char* src) {
  size_t length = strlen(src) / 2;
  if (src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) {
    src += 2;
    length--;
  }
  for (size_t i = 0; i < length; i++) {
    buf[i] = (getbin(src[i * 2]) << 4) | getbin(src[i * 2 + 1]);
  }
  return length;
}

void set_basic_data() {
  xudt_set_flags(1);
  xudt_add_input_amount(999);
  xudt_add_output_amount(999);

  // lock script hash
  uint8_t input_lock_script_hash[32] = {11};
  uint8_t output_lock_script_hash[32] = {22};
  xudt_add_input_lock_script_hash(input_lock_script_hash);
  xudt_add_output_lock_script_hash(output_lock_script_hash);
}

// the following hash_root, proof pairs are verified successfully
// with the following lock script hash:
//  uint8_t input_lock_script_hash[32] = {11};
//  uint8_t output_lock_script_hash[32] = {22};

uint8_t BLACK_LIST_HASH_ROOT[32] = {
    126, 135, 248, 129, 55,  74, 37, 2,  200, 13,  112, 6,  225, 50, 60, 119,
    17,  26,  212, 53,  176, 39, 79, 18, 40,  147, 224, 67, 94,  50, 10, 130};
uint8_t BLACK_LIST_PROOF[] = {
    76, 79,  3,   81,  2,   107, 31,  136, 57, 101, 46,  172, 224, 208, 71,
    81, 138, 235, 101, 93,  254, 147, 224, 69, 164, 216, 73,  120, 175, 255,
    83, 63,  60,  252, 171, 50,  90,  0,   0,  0,   0,   0,   0,   0,   0,
    0,  0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,   0,   0,
    0,  0,   0,   0,   0,   0,   0,   0,   0,  76,  79,  4,   72,  79,  251};

uint8_t WHITE_LIST_HASH_ROOT[32] = {121, 187, 51,  140, 11,  10,  158, 101,
                                    156, 132, 190, 246, 8,   83,  151, 51,
                                    128, 51,  8,   199, 110, 150, 151, 174,
                                    54,  156, 56,  94,  100, 186, 73,  119};
uint8_t WHITE_LIST_PROOF[] = {76, 79, 4, 76, 79, 4, 72, 79, 251};

void set_rce_not_on_black_list_data() {
  int err = 0;
  set_basic_data();
  uint16_t root_rcrule =
      rce_add_rcrule(BLACK_LIST_HASH_ROOT, 0x0);  // black list
  rce_begin_proof();
  rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF), 0x3);
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
}

void set_rce_on_black_list_data() {
  int err = 0;
  set_basic_data();
  uint8_t hash[32] = {
      0};  // invalid hash, so the verify result is false: it's on black list.
  uint16_t root_rcrule = rce_add_rcrule(hash, 0x0);  // on black list
  rce_begin_proof();
  rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF), 0x3);
  rce_end_proof();

  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
}

UTEST(xudt, main) {
  int err = 0;

  // prepare basic data
  xudt_begin_data();
  set_basic_data();

  uint8_t hash0[BLAKE2B_BLOCK_SIZE] = {0};
  uint8_t hash1[BLAKE2B_BLOCK_SIZE] = {1};
  uint8_t extension_hash[BLAKE2B_BLOCK_SIZE] = {0x66};
  uint8_t args[32] = {0};
  xudt_set_owner_mode(hash0, hash1);
  xudt_add_extension_script(
      extension_hash, 1, args, sizeof(args),
      "tests/xudt_rce/simulator-build-debug/libextension_script_0.dylib");

  xudt_end_data();

  // flags = 1
  xudt_set_flags(1);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);
  // flags = 2
  xudt_set_flags(2);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);
  // flags is not available
  xudt_set_flags(0);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);
  // flags is available, but it's value is 0,
  // Note: testing purpose, there is no such 0xFF flags.
  xudt_set_flags(0xFF);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);

  // owner mode is true
  xudt_set_owner_mode(hash0, hash0);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);

  err = 0;
exit:
  ASSERT_EQ(err, 0);
}

UTEST(xudt_many_scripts, main) {
  int err = 0;

  // prepare basic data
  xudt_begin_data();
  set_basic_data();

  uint8_t hash0[BLAKE2B_BLOCK_SIZE] = {0};
  uint8_t hash1[BLAKE2B_BLOCK_SIZE] = {1};
  uint8_t extension_hash[BLAKE2B_BLOCK_SIZE] = {0x66};
  uint8_t args[32] = {0};
  xudt_set_owner_mode(hash0, hash1);

  for (int i = 0; i < 512; i++) {
    xudt_add_extension_script(
        extension_hash, 1, args, sizeof(args),
        "tests/xudt_rce/simulator-build-debug/libextension_script_0.dylib");
  }

  xudt_end_data();

  // when flags = 1, The extension script data is on args:
  // it's too small to hold all these data
  xudt_set_flags(1);
  err = simulator_main();
  ASSERT_EQ(err, -1);

  // flags = 2
  xudt_set_flags(2);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);

  err = 0;
exit:
  ASSERT_EQ(err, 0);
}

UTEST(rce, white_list) {
  int err = 0;
  xudt_begin_data();
  set_basic_data();
  uint16_t root_rcrule =
      rce_add_rcrule(WHITE_LIST_HASH_ROOT, 0x2);  // white list
  rce_begin_proof();
  rce_add_proof(WHITE_LIST_PROOF, countof(WHITE_LIST_PROOF), 0x3);
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(err, 0);
exit:
  return;
}

UTEST(rce, both_input_and_output_on_white_list) {
  int err = 0;
  xudt_begin_data();
  set_basic_data();

  //   --include "0" 11 22
  uint8_t hash_root1[] = {121, 187, 51, 140, 11, 10,  158, 101, 156, 132, 190,
                          246, 8,   83, 151, 51, 128, 51,  8,   199, 110, 150,
                          151, 174, 54, 156, 56, 94,  100, 186, 73,  119};
  uint8_t proof1[] = {76,  79,  4,   81, 4,   183, 161, 135, 240, 168, 177, 241,
                      159, 252, 171, 12, 137, 59,  35,  168, 236, 254, 11,  18,
                      23,  44,  30,  23, 44,  151, 165, 109, 24,  54,  198, 17,
                      34,  6,   0,   0,  0,   0,   0,   0,   0,   0,   0,   0,
                      0,   0,   0,   0,  0,   0,   0,   0,   0,   0,   0,   0,
                      0,   0,   0,   0,  0,   0,   0,   0,   0,   79,  251};

  //   --include "1" 11 22
  uint8_t hash_root2[] = {121, 187, 51, 140, 11, 10,  158, 101, 156, 132, 190,
                          246, 8,   83, 151, 51, 128, 51,  8,   199, 110, 150,
                          151, 174, 54, 156, 56, 94,  100, 186, 73,  119};
  uint8_t proof2[] = {
      76,  79,  4,   81, 4,   79,  165, 120, 195, 32, 225, 87, 101, 216, 104,
      215, 165, 4,   63, 251, 58,  229, 109, 123, 59, 26,  8,  183, 190, 133,
      142, 28,  222, 5,  23,  175, 72,  11,  0,   0,  0,   0,  0,   0,   0,
      0,   0,   0,   0,  0,   0,   0,   0,   0,   0,  0,   0,  0,   0,   0,
      0,   0,   0,   0,  0,   0,   0,   0,   0,   79, 251};

  uint16_t rcrulevec[MAX_RCRULE_IN_CELL] = {0};
  rcrulevec[0] = rce_add_rcrule(hash_root1, 0x2);
  rcrulevec[1] = rce_add_rcrule(hash_root2, 0x2);
  RCHashType root_rcrule = rce_add_rccellvec(rcrulevec, 2);

  rce_begin_proof();
  rce_add_proof(proof1, countof(proof1), 0x1);  // input
  rce_add_proof(proof2, countof(proof2), 0x2);  // output
  rce_end_proof();

  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(err, 0);
exit:
  return;
}

UTEST(rce, only_input_on_white_list) {
  int err = 0;
  xudt_begin_data();
  set_basic_data();

  uint8_t hash_root1[] = {151, 81,  37,  242, 189, 99, 62,  175, 115, 9,   251,
                          94,  105, 190, 173, 153, 42, 249, 87,  115, 253, 152,
                          110, 88,  1,   58,  224, 21, 51,  99,  72,  182};
  uint8_t proof1[] = {76,  80,  4,   157, 181, 3,   109, 35,  79,  233, 114, 91,
                      219, 188, 99,  77,  45,  214, 230, 222, 170, 154, 162, 63,
                      51,  85,  254, 115, 15,  23,  166, 5,   21,  254, 51};

  uint8_t hash_root2[] = {151, 81,  37,  242, 189, 99, 62,  175, 115, 9,   251,
                          94,  105, 190, 173, 153, 42, 249, 87,  115, 253, 152,
                          110, 88,  1,   58,  224, 21, 51,  99,  72,  182};
  hash_root2[0] = 0;  // make output not on white list
  uint8_t proof2[] = {76, 80,  4,   96,  186, 33,  226, 13, 35,  104, 150, 165,
                      4,  223, 103, 18,  193, 40,  37,  99, 107, 99,  12,  175,
                      14, 142, 165, 116, 90,  255, 239, 90, 63,  128, 35};

  uint16_t rcrulevec[MAX_RCRULE_IN_CELL] = {0};
  rcrulevec[0] = rce_add_rcrule(hash_root1, 0x2);
  rcrulevec[1] = rce_add_rcrule(hash_root2, 0x2);
  RCHashType root_rcrule = rce_add_rccellvec(rcrulevec, 2);

  rce_begin_proof();
  rce_add_proof(proof1, countof(proof1), 0x1);  // input
  rce_add_proof(proof2, countof(proof2), 0x2);  // output
  rce_end_proof();

  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(ERROR_NOT_ON_WHITE_LIST, err);
exit:
  return;
}

UTEST(rce, not_on_white_list) {
  int err = 0;
  xudt_begin_data();
  set_basic_data();

  uint8_t rcrule[32] = {0};                            // invalid root_hash
  uint16_t root_rcrule = rce_add_rcrule(rcrule, 0x2);  // white list
  uint8_t proof[] = {76, 76, 72, 4};
  rce_begin_proof();
  rce_add_proof(proof, countof(proof), 0x3);
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(err, ERROR_NOT_ON_WHITE_LIST);
exit:
  return;
}

UTEST(smt, verify_not_on_bl) {
  uint8_t key1[32] = {11};
  uint8_t value1[32] = {0};
  uint8_t key2[32] = {22};
  uint8_t value2[32] = {0};

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key1, value1);
  smt_state_insert(&changes, key2, value2);
  smt_state_normalize(&changes);

  int err = smt_verify(BLACK_LIST_HASH_ROOT, &changes, BLACK_LIST_PROOF,
                       sizeof(BLACK_LIST_PROOF));
  ASSERT_EQ(0, err);
}

UTEST(rce, black_list) {
  int err = 0;
  xudt_begin_data();
  set_basic_data();
  uint16_t root_rcrule =
      rce_add_rcrule(BLACK_LIST_HASH_ROOT, 0x0);  // black list
  rce_begin_proof();
  rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF), 0x3);
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();
  err = simulator_main();
  ASSERT_EQ(0, err);
exit:
  return;
}

UTEST(xudt, simple_udt) {
  int err = 0;
  xudt_begin_data();
  set_rce_not_on_black_list_data();
  xudt_add_input_amount(999);
  xudt_add_output_amount(1000);
  xudt_end_data();
  err = simulator_main();
  ASSERT_EQ(err, ERROR_AMOUNT);

exit:
  return;
}

UTEST(xudt, emergency_halt_mode) {
  int err = 0;
  xudt_begin_data();
  xudt_set_flags(2);

  uint16_t root_rcrule = rce_add_rcrule(
      BLACK_LIST_HASH_ROOT, 0x1);  // emergency halt mode, black list
  rce_begin_proof();
  rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF), 0x3);
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();
  err = simulator_main();
  ASSERT_EQ(err, ERROR_RCE_EMERGENCY_HALT);
exit:
  return;
}

UTEST(xudt, extension_script_is_validated) {
  int err = 0;

  xudt_begin_data();

  xudt_set_flags(1);
  xudt_add_input_amount(999);
  xudt_add_output_amount(999);
  uint8_t extension_hash[BLAKE2B_BLOCK_SIZE] = {0x66};
  uint8_t args[32] = {0};

  xudt_add_extension_script(
      extension_hash, 1, args, sizeof(args),
      "tests/xudt_rce/simulator-build-debug/libextension_script_0.dylib");
  uint8_t hash[32];
  xudt_calc_extension_script_hash(extension_hash, 1, args, sizeof(args), hash);
  uint8_t output_lock_script_hash[32] = {22};
  // extension script hash is identical to lock script hash
  xudt_add_input_lock_script_hash(hash);
  xudt_add_output_lock_script_hash(output_lock_script_hash);

  // finish data
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(err, 0);
exit:
  return;
}

UTEST(xudt, extension_script_returns_non_zero) {
  int err = 0;
  xudt_begin_data();
  set_rce_on_black_list_data();
  uint8_t extension_hash[BLAKE2B_BLOCK_SIZE] = {0x66};
  uint8_t args[32] = {0};
  xudt_add_extension_script(
      extension_hash, 1, args, sizeof(args),
      "tests/xudt_rce/simulator-build-debug/libextension_script_1.dylib");
  xudt_end_data();
  err = simulator_main();
  ASSERT_EQ(ERROR_ON_BLACK_LIST, err);

exit:
  return;
}

UTEST(rce, use_rc_cell_vec) {
  int err = 0;
  // prepare basic data
  xudt_begin_data();
  set_basic_data();
  uint16_t rcrulevec[MAX_RCRULE_IN_CELL] = {0};
  for (int i = 0; i < MAX_RCRULE_IN_CELL; i++) {
    rcrulevec[i] =
        rce_add_rcrule(BLACK_LIST_HASH_ROOT, 0x0);  // not on black list
  }
  RCHashType root_rcrule = rce_add_rccellvec(rcrulevec, MAX_RCRULE_IN_CELL);
  rce_begin_proof();
  for (int i = 0; i < MAX_RCRULE_IN_CELL; i++) {
    rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF), 0x3);
  }
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(0, err);
exit:
  return;
}

UTEST(smt, verify_not_existing) {
  uint8_t key1[32] = {11};
  uint8_t value1[32] = {0};
  uint8_t key2[32] = {22};
  uint8_t value2[32] = {0};
  // --exclude "11|22" 0 1
  uint8_t root_hash[32] = {126, 135, 248, 129, 55,  74, 37, 2,   200, 13,  112,
                           6,   225, 50,  60,  119, 17, 26, 212, 53,  176, 39,
                           79,  18,  40,  147, 224, 67, 94, 50,  10,  130};
  uint8_t proof[] = {
      76, 79,  3,   81,  2,   107, 31,  136, 57, 101, 46,  172, 224, 208, 71,
      81, 138, 235, 101, 93,  254, 147, 224, 69, 164, 216, 73,  120, 175, 255,
      83, 63,  60,  252, 171, 50,  90,  0,   0,  0,   0,   0,   0,   0,   0,
      0,  0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,   0,   0,
      0,  0,   0,   0,   0,   0,   0,   0,   0,  76,  79,  4,   72,  79,  251};

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key1, value1);
  smt_state_insert(&changes, key2, value2);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, sizeof(proof)));
}

UTEST(smt, verify_last_byte_is_0x48) {
  // --include "0|1" 11
  // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  uint8_t key1[32] = {11};
  uint8_t value1[32] = {1};
  uint8_t key2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t value2[32] = {1};
  uint8_t root_hash[32] = {186, 238, 33,  242, 95,  185, 159, 239,
                           2,   142, 238, 46,  209, 248, 223, 148,
                           228, 225, 128, 18,  35,  190, 17,  41,
                           236, 47,  207, 230, 217, 247, 145, 191};
  uint8_t proof[] = {76, 79, 255, 76, 79, 255, 72};  // 72 is 0x48

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key1, value1);
  smt_state_insert(&changes, key2, value2);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, sizeof(proof)));
}

// this is the case from
// https://github.com/nervosnetwork/ckb-simple-account-layer/blob/1970c0382271837ff46fdc276c5b63bccb4324db/c/tests/main.c#L136
// the names are changed accordingly.
// --hex --kvpair --exclude
// 0x0101010101010101010101010101010101010101010101010101010101010101 1 1
UTEST(smt, verify_empty) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0x0101010101010101010101010101010101010101010101010101010101010101");
  hex2bin(value,
          "0x0000000000000000000000000000000000000000000000000000000000000000");
  hex2bin(root_hash,
          "0x2e53c97352a7a7d126e96ace29acbdd1ccadb7ce01fae60e45eb1140002ca5e4");
  int proof_length = hex2bin(proof,
                             "0x4c4ff851f833522063667f32b6cc23ef966e0dfd6407425"
                             "c7cd7ea87156303e7be9cc37a4f0100000000000000000000"
                             "0000000000000000000000000000000000000000004f07");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

// --hex --kvpair --exclude
// 0x0101010101010101010101010101010101010101010101010101010101010101 1 1
UTEST(smt, verify_empty2) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0x0101010101010101010101010101010101010101010101010101010101010101");
  hex2bin(value,
          "0x0000000000000000000000000000000000000000000000000000000000000000");
  hex2bin(root_hash,
          "0x0f39878077162cf8a5e9455c28956dd2f460b5b8bba5389336b8fdb5032263c7");
  int proof_length = hex2bin(proof,
                             "0x4c4ff851f8ece253fdd24dc8e1b991b6f6fd0a537caa0de"
                             "a20f4093844a79de77d33972e480100000000000000000000"
                             "0000000000000000000000000000000000000000004f07");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

// --hex --kvpair --include "0"
// 0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b
// 0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b 11 11
UTEST(smt, verify1) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  hex2bin(root_hash,
          "0xebe0fab376cd802d364eeb44af20c67a74d6183a33928fead163120ef12e6e06");
  int proof_length = hex2bin(
      proof,
      "0x4c4fff51ff322de8a89fe589987f97220cfcb6820bd798b31a0b56ffea221093d35f90"
      "9e580b00000000000000000000000000000000000000000000000000000000000000");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

// run -- --hex --kvpair --include "0"
// 0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a
// 0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82  11 11 22
// 22
UTEST(smt, verify2) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  hex2bin(root_hash,
          "0x6e5c722644cd55cef8c4ed886cd8b44027ae9ed129e70a4b67d87be1c6857842");
  int proof_length = hex2bin(
      proof,
      "0x4c4fff51fa8aaa2aece17b92ec3f202a40a09f7286522bae1e5581a2a49195ab6781b1"
      "b8090000000000000000000000000000000000000000000000000000000000000000");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

// run -- --hex --kvpair --include "0"
// 0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5
// 0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb    11 11
// 22 22
UTEST(smt, verify3) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  hex2bin(root_hash,
          "0xc8f513901e34383bcec57c368628ce66da7496df0a180ee1e021df3d97cb8f7b");
  int proof_length = hex2bin(
      proof,
      "0x4c4fff51fa8aaa2aece17b92ec3f202a40a09f7286522bae1e5581a2a49195ab6781b1"
      "b8090000000000000000000000000000000000000000000000000000000000000000");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_invalid_hash) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50fe32845309d34f132cd6f7ac6a7881962401adc35c19a18d4fffeb511b97ea"
      "bf86");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_NE(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_all_leaves_used) {}

// --hex --kvpair --include '0|1'
// 0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5
// 0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb
// 0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e6
// 0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19ec
UTEST(smt, verify_multi_2) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xae39dd03298b9fe839358b3dd68bc45794c0598aa7ebfc147b9b5c228e7e67cc");
  int proof_length = hex2bin(proof, "0x4c4ff94c4ff9484f06");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e6");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19ec");
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

//  --hex --kvpair --include '0|1|2'
//  0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5
//  0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb
//  0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b
//  0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b
//  0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a
//  0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82
UTEST(smt, verify_multi_3) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0x35fb14c8d5994f8871d7a107cbf3be05db578c6dbd0a731c3cee241eccc77d82");
  int proof_length = hex2bin(proof, "0x4c4ff84c4ff8484f054c4ffe484f01");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_invalid_height) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(proof, "0x4c4c48204c4840");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_NE(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, update) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t expected_hash[32];
  uint8_t proof[96];
  smt_pair_t entries[8];
  smt_state_t changes;

  memset(root_hash, 0, 32);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  int proof_length = hex2bin(proof, "0x4c4f00");
  memset(&proof[32], 0, 64);
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);
  ASSERT_EQ(0, smt_calculate_root(root_hash, &changes, proof, proof_length));
  // --hex --kvpair --include "0"
  // 0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a
  // 0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82
  hex2bin(expected_hash,
          "0xd75c4d6624ce668856d9a382c45276a2c06ba7065192d8bb805d48e106a4136d");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));

  // run -- --hex --kvpair --include "0"
  // 0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b
  // 0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b
  // 11
  // 11
  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  proof_length = hex2bin(
      proof,
      "0x4c4fff51ff322de8a89fe589987f97220cfcb6820bd798b31a0b56ffea221093d35f90"
      "9e580b00000000000000000000000000000000000000000000000000000000000000");
  memset(&proof[64], 0, 32);
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);
  ASSERT_EQ(0, smt_calculate_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0xebe0fab376cd802d364eeb44af20c67a74d6183a33928fead163120ef12e6e06");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  proof_length = hex2bin(proof, "0x4c4f00");
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);
  ASSERT_EQ(0, smt_calculate_root(root_hash, &changes, proof, proof_length));
  // --hex --kvpair --include "0"
  // 0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5
  // 0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb
  hex2bin(expected_hash,
          "0xc4cb09d4ffc0cad781fa2b64bd67a587e4107fe67eed7dee833e8f349d9596f5");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));
}

// naive implementation, get element at "index" , not counting "zero" element.
uint8_t get_from_table(uint8_t* table, int len, int index) {
  int true_index = -1;
  for (int i = 0; i < len; i++) {
    if (table[i] != 0) {
      true_index++;
    }
    if (true_index == index) {
      return table[i];
    }
  }
  ASSERT(false);
  return 0xFF;
}

bool test_state_normalize_random() {
  uint8_t table[8] = {0};
  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, countof(entries));
  char msg_to_print[32768] = {0};
  int msg_start = 0;
  for (int i = 0; i < countof(entries); i++) {
    int key = rand() % 8;
    table[key] += 1;

    uint8_t key32[32] = {key};
    uint8_t value32[32] = {table[key]};
    int used = sprintf(msg_to_print + msg_start,
                       "pushed key = %d, value = %d\n", key, table[key]);
    msg_start += used;
    smt_state_insert(&changes, key32, value32);
  }
  smt_state_normalize(&changes);
  for (int i = 0; i < changes.len; i++) {
    uint8_t expected = get_from_table(table, countof(entries), i);
    if (changes.pairs[i].value[0] != expected) {
      printf("%s\n", msg_to_print);
      printf("changes.pairs[%d].key[0] = %d, changes.pairs[%d].value[0] = %d\n",
             i, changes.pairs[i].key[0], i, changes.pairs[i].value[0]);
      printf("expected = %d\n", expected);
      return false;
    }
  }
  return true;
}

UTEST(smt, test_state_normalize) {
  for (int i = 0; i < 10000; i++) {
    bool result = test_state_normalize_random();
    ASSERT_TRUE(result);
  }
}

UTEST_MAIN();
