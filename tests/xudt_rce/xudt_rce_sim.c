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

uint8_t BLACK_LIST_HASH_ROOT[32] = {121, 127, 78,  214, 231, 172, 41,  53,
                                    107, 94,  203, 98,  176, 206, 210, 159,
                                    244, 78,  27,  16,  55,  143, 233, 241,
                                    40,  121, 79,  244, 222, 150, 136, 137};
uint8_t BLACK_LIST_PROOF[] = {
    76,  79,  4,   76,  79,  4,   72,  79,  1,   80,  68,  166, 240,
    37,  234, 147, 239, 73,  241, 170, 252, 24,  233, 166, 13,  8,
    144, 122, 200, 58,  112, 81,  253, 153, 233, 209, 147, 183, 52,
    155, 85,  36,  80,  198, 252, 191, 18,  88,  112, 77,  185, 211,
    179, 13,  34,  7,   199, 106, 69,  171, 141, 45,  88,  159, 113,
    109, 12,  63,  4,   100, 18,  126, 233, 206, 7,   79,  248};

uint8_t WHITE_LIST_HASH_ROOT[32] = {235, 105, 210, 194, 186, 219, 171, 181,
                                    169, 162, 220, 64,  221, 213, 52,  91,
                                    187, 59,  99,  192, 244, 1,   14,  56,
                                    150, 148, 52,  203, 11,  89,  95,  209};
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

  uint8_t hash_root1[] = {235, 105, 210, 194, 186, 219, 171, 181, 169, 162, 220,
                          64,  221, 213, 52,  91,  187, 59,  99,  192, 244, 1,
                          14,  56,  150, 148, 52,  203, 11,  89,  95,  209};
  uint8_t proof1[] = {76,  79,  4,   80,  58,  202, 6,   201, 251, 46,
                      183, 51,  211, 183, 198, 250, 208, 62,  52,  163,
                      250, 80,  8,   117, 112, 98,  196, 129, 140, 105,
                      65,  143, 93,  89,  246, 166, 79,  251};

  uint8_t hash_root2[] = {235, 105, 210, 194, 186, 219, 171, 181, 169, 162, 220,
                          64,  221, 213, 52,  91,  187, 59,  99,  192, 244, 1,
                          14,  56,  150, 148, 52,  203, 11,  89,  95,  209};
  uint8_t proof2[] = {76,  79,  4,   80,  7,   254, 28,  186, 6,   69,
                      212, 48,  120, 112, 200, 117, 139, 175, 188, 251,
                      98,  186, 61,  215, 102, 198, 181, 210, 37,  254,
                      148, 30,  164, 112, 118, 218, 79,  251};

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
  uint8_t root_hash[32] = {121, 127, 78,  214, 231, 172, 41,  53,  107, 94, 203,
                           98,  176, 206, 210, 159, 244, 78,  27,  16,  55, 143,
                           233, 241, 40,  121, 79,  244, 222, 150, 136, 137};
  uint8_t proof[] = {76,  79,  4,   76,  79,  4,   72,  79,  1,   80,  68,
                     166, 240, 37,  234, 147, 239, 73,  241, 170, 252, 24,
                     233, 166, 13,  8,   144, 122, 200, 58,  112, 81,  253,
                     153, 233, 209, 147, 183, 52,  155, 85,  36,  80,  198,
                     252, 191, 18,  88,  112, 77,  185, 211, 179, 13,  34,
                     7,   199, 106, 69,  171, 141, 45,  88,  159, 113, 109,
                     12,  63,  4,   100, 18,  126, 233, 206, 7,   79,  248};

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
          "0x64fb91a9319ff2b3169f2127b5781bbc01d29258e1f946401fef812ef2182deb");
  int proof_length = hex2bin(proof,
                             "0x4c4ff85029720fdae893cd8e7291da6c0d1e9341d796cb2"
                             "8999762b64f99151a86c5cb504f07");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

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
          "0x797f4ed6e7ac29356b5ecb62b0ced29ff44e1b10378fe9f128794ff4de968889");
  int proof_length = hex2bin(proof,
                             "0x4c4ff850b33575f3031d5a0bb435aabaa9b1040b69cc31b"
                             "09c0512091a0165966ef9300e4f07");

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
          "0x28b0daae982888947a3d75259c21247143008b3de07b136ddc1148c2cc9d0c0b");
  int proof_length = hex2bin(proof,
                             "0x4c4fff500881fe7c405d49f5067dfed14bea9297a98b9c3"
                             "b161ee221e8f58d12724bd423");

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
          "0x5d2aa5a8202e72d1303488143028f10d5aa058833f0891dd51efdc8f7b65389f");
  int proof_length = hex2bin(proof,
                             "0x4c4fff50742b531400f57913260f51ecc70cf11594643cf"
                             "36623f69c0c2abd3c829d0d29");

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
          "0x10379090a0ce3998203c1ba23f20125b334c6591db9695c885a4421b6dceb1f5");
  int proof_length = hex2bin(proof,
                             "0x4c4fff50742b531400f57913260f51ecc70cf11594643cf"
                             "36623f69c0c2abd3c829d0d29");

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
          "0xbe4491873980f79d92808d6f8435335995c1578792f36aca5f8794b7b1320976");
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
          "0x3752245c0d68fe0f7c00cfed7bd587935871a80ea170468b2aa0e9d681188bfa");
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
  hex2bin(expected_hash,
          "0x838fb1557ded00b1eaa321ba217bcb90546c1f05ec6b9cde724241c785b6efc9");
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
  proof_length = hex2bin(proof,
                         "0x4c4fff500881fe7c405d49f5067dfed14bea9297a98b9c3b161"
                         "ee221e8f58d12724bd423");
  memset(&proof[64], 0, 32);
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);
  ASSERT_EQ(0, smt_calculate_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0x28b0daae982888947a3d75259c21247143008b3de07b136ddc1148c2cc9d0c0b");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  proof_length = hex2bin(proof,
                         "0x4c4fff500881fe7c405d49f5067dfed14bea9297a98b9c3b161"
                         "ee221e8f58d12724bd423");
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);
  ASSERT_EQ(0, smt_calculate_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0xdd20f7c39619ce2828dfcd3bd40c54432e736bbefdeaab6f48ed6e668130336a");
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
