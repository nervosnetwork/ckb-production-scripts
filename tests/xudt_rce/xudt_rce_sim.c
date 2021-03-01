
// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>

#if defined(CKB_COVERAGE) || defined(CKB_RUN_IN_VM)
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
  xudt_set_owner_mode(hash0, hash1);
  xudt_add_extension_script_hash(
      extension_hash, 1,
      "tests/xudt_rce/cmake-build-debug/libextension_script_0.dylib");
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

// this is the case from
// https://github.com/nervosnetwork/ckb-simple-account-layer/blob/1970c0382271837ff46fdc276c5b63bccb4324db/c/tests/main.c#L136
// the names are changed accordingly.
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

UTEST_MAIN();
