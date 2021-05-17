#if defined(CKB_COVERAGE)
#define ASSERT(s) (void)0
#else
#define ASSERT(s) (void)0
#endif

int ckb_exit(signed char code);

#include "rc_lock.c"
#include "utest.h"
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

UTEST(pubkey_hash, pass) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsPubkeyHash;
  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(pubkey_hash, wrong_signature) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsPubkeyHash;

  g_setting.wrong_signature = true;
  convert_setting_to_states();

  int r = simulator_main();
  bool b = (r == ERROR_PUBKEY_BLAKE160_HASH || r == ERROR_SECP_RECOVER_PUBKEY ||
            r == ERROR_SECP_PARSE_SIGNATURE);
  ASSERT_TRUE(b);
}

UTEST(pubkey_hash, wrong_pubkey_hash) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsPubkeyHash;

  g_setting.wrong_pubkey_hash = true;
  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_PUBKEY_BLAKE160_HASH, r);
}

UTEST(owner_lock, pass) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsOwnerLock;

  uint8_t blake160[20] = {0xBE, 0xEF};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(owner_lock, not_pass) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsOwnerLock;

  uint8_t blake160[20] = {0xBE, 0xEF};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;
  g_setting.input_lsh_count = 1;

  g_setting.blake160[0] = 0x00;

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_LOCK_SCRIPT_HASH_NOT_FOUND, r);
}

UTEST_MAIN();
