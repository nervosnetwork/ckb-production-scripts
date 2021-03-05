
// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>
#define CKB_COVERAGE
#if defined(CKB_COVERAGE)
#define ASSERT(s) (void)0
#else
#include <assert.h>
#define ASSERT assert
#endif

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

UTEST(xudt, main) {
  int err = 0;

  // prepare basic data
  uint8_t hash0[BLAKE2B_BLOCK_SIZE] = {0};
  uint8_t hash1[BLAKE2B_BLOCK_SIZE] = {1};
  uint8_t extension_hash[BLAKE2B_BLOCK_SIZE] = {0x66};
  xudt_begin_data();
  xudt_set_flags(1);
  // not owner mode
  uint8_t args[32] = {0};
  xudt_set_owner_mode(hash0, hash1);
  xudt_add_extension_script_hash(
      extension_hash, 1, args, sizeof(args),
      "tests/xudt_rce/simulator-build-debug/libextension_script_0.dylib");
  xudt_add_input_amount(999);
  xudt_add_output_amount(999);
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
  // flags = 0
  xudt_set_flags(0);
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

UTEST(rce, white_list) {
  int err = 0;
  // prepare basic data
  xudt_begin_data();
  set_basic_data();

  // rcrool and proof should 1:1
  // rc rule
  uint8_t rcrule[32] = {151, 81,  37,  242, 189, 99, 62,  175, 115, 9,   251,
                        94,  105, 190, 173, 153, 42, 249, 87,  115, 253, 152,
                        110, 88,  1,   58,  224, 21, 51,  99,  72,  182};
  uint16_t root_rcrule = rce_add_rcrule(rcrule, 0x2);  // white list
  // proof
  uint8_t proof[] = {76, 76, 72, 4};
  rce_begin_proof();
  rce_add_proof(proof, countof(proof));
  rce_end_proof();
  //
  xudt_add_extension_script_hash(RCE_HASH, 1, (uint8_t*)&root_rcrule, 32,
                                 "internal extension script, no path");

  // finish data
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(err, 0);
exit:
  return;
}

UTEST(rce, black_list) {
  int err = 0;

  // prepare basic data
  xudt_begin_data();
  set_basic_data();

  // rcrule and proof should 1:1
  // rc rule
  uint8_t rcrule[32] = {143, 95, 66, 207, 251, 51,  58,  199, 247, 61,  211,
                        60,  28, 25, 51,  99,  174, 94,  226, 239, 134, 201,
                        125, 79, 63, 194, 180, 109, 161, 2,   92,  178};
  uint16_t root_rcrule = rce_add_rcrule(rcrule, 0x0);  // black list
  // proof
  uint8_t proof[] = {
      76,  76,  72,  4,   80,  6,   62,  195, 223, 65,  89,  79,  50, 133, 172,
      95,  118, 228, 237, 101, 113, 8,   175, 152, 171, 153, 202, 45, 125, 177,
      0,   236, 236, 176, 183, 31,  109, 113, 80,  7,   88,  178, 89, 155, 132,
      146, 222, 163, 40,  147, 106, 150, 97,  234, 134, 107, 237, 60, 9,   193,
      0,   16,  226, 17,  209, 89,  52,  22,  71,  135, 172, 225};
  rce_begin_proof();
  rce_add_proof(proof, countof(proof));
  rce_end_proof();
  //
  xudt_add_extension_script_hash(RCE_HASH, 1, (uint8_t*)&root_rcrule, 32,
                                 "internal extension script, no path");

  // finish data
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(err, 0);
exit:
  return;
}

UTEST(smt, verify_not_existing) {
  uint8_t key1[32] = {11};
  uint8_t value1[32] = {0};
  uint8_t key2[32] = {22};
  uint8_t value2[32] = {0};
  uint8_t root_hash[32] = {143, 95, 66, 207, 251, 51,  58,  199, 247, 61,  211,
                           60,  28, 25, 51,  99,  174, 94,  226, 239, 134, 201,
                           125, 79, 63, 194, 180, 109, 161, 2,   92,  178};
  uint8_t proof[] = {
      76,  76,  72,  4,   80,  6,   62,  195, 223, 65,  89,  79,  50, 133, 172,
      95,  118, 228, 237, 101, 113, 8,   175, 152, 171, 153, 202, 45, 125, 177,
      0,   236, 236, 176, 183, 31,  109, 113, 80,  7,   88,  178, 89, 155, 132,
      146, 222, 163, 40,  147, 106, 150, 97,  234, 134, 107, 237, 60, 9,   193,
      0,   16,  226, 17,  209, 89,  52,  22,  71,  135, 172, 225};

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key1, value1);
  rce_state_insert(&changes, key2, value2);
  rce_state_normalize(&changes);

  ASSERT_EQ(0, rce_smt_verify(root_hash, &changes, proof, sizeof(proof)));
}
// this is the case from
// https://github.com/nervosnetwork/ckb-simple-account-layer/blob/1970c0382271837ff46fdc276c5b63bccb4324db/c/tests/main.c#L136
// the names are changed accordingly.
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
          "0x0000000000000000000000000000000000000000000000000000000000000000");
  int proof_length = hex2bin(proof, "0x4c");

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);

  ASSERT_EQ(0, rce_smt_verify(root_hash, &changes, proof, proof_length));
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
          "0x27cdd63d6d03e2a8dfc28d1919def1324b11b44733937ce66b8cf343a2fb536e");
  int proof_length = hex2bin(proof,
                             "0x4c50f027cdd63d6d03e2a8dfc28d1919def1324b11b4473"
                             "3937ce66b8cf343a2fb536e");

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);

  ASSERT_EQ(0, rce_smt_verify(root_hash, &changes, proof, proof_length));
}

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
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50f85faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f372c1"
      "50fe3f2a0a59ba1081f2d343682b200a778191a4e5838a46774eda8e1ee201c6cb2f");

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);

  ASSERT_EQ(0, rce_smt_verify(root_hash, &changes, proof, proof_length));
}

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
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50f8a9cee9b111fddde5dd16c6684715587ba628bf73407e03e9db579e41af0c09b8"
      "50fe3f2a0a59ba1081f2d343682b200a778191a4e5838a46774eda8e1ee201c6cb2f");

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);

  ASSERT_EQ(0, rce_smt_verify(root_hash, &changes, proof, proof_length));
}

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
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50fe32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb511b97ea"
      "bf86");

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);

  ASSERT_EQ(0, rce_smt_verify(root_hash, &changes, proof, proof_length));
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

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);

  ASSERT_NE(0, rce_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_all_leaves_used) {}

UTEST(smt, verify_multi_2) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xaa84c1a9b237e29e78bf2c59539e0ab2aa4ddd727f1d43bda03cc37ca9c523ca");
  int proof_length = hex2bin(
      proof,
      "0x4c4c48f950fe32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb51"
      "1b97eabf86");

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  rce_state_insert(&changes, key, value);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e6");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19ec");
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);

  ASSERT_EQ(0, rce_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_multi_3) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(proof, "0x4c4c48f84c48fe");

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  rce_state_insert(&changes, key, value);
  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  rce_state_insert(&changes, key, value);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);

  ASSERT_EQ(0, rce_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_invalid_height) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(proof, "0x4c4c48204c4840");

  rce_pair_t entries[8];
  rce_state_t changes;
  rce_state_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  rce_state_insert(&changes, key, value);
  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  rce_state_insert(&changes, key, value);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);

  ASSERT_NE(0, rce_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, update) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t expected_hash[32];
  uint8_t proof[96];
  rce_pair_t entries[8];
  rce_state_t changes;

  memset(root_hash, 0, 32);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  int proof_length = hex2bin(proof, "0x4c");
  memset(&proof[32], 0, 64);
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);
  ASSERT_EQ(0,
            rce_smt_calculate_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0x5faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f372c1");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));

  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  proof_length = hex2bin(
      proof,
      "0x4c50f85faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f3"
      "72c1");
  memset(&proof[64], 0, 32);
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);
  ASSERT_EQ(0,
            rce_smt_calculate_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0x32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb511b97eabf86");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  proof_length = hex2bin(
      proof,
      "0x4c50fe32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb511b97ea"
      "bf86");
  rce_state_init(&changes, entries, 32);
  rce_state_insert(&changes, key, value);
  rce_state_normalize(&changes);
  ASSERT_EQ(0,
            rce_smt_calculate_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));
}

UTEST_MAIN();
