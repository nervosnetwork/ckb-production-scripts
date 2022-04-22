#if defined(CKB_COVERAGE)
#define ASSERT(s) (void)0
#endif

int ckb_exit(signed char code);

// clang-format off
#include "taproot_lock.c"
#include "ckb_syscall_taproot_lock_impl.h"
#include "utest.h"
// clang-format on

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

UTEST(key_path_spending, success) {
  init_input();
  g_setting.flags = 6;
  g_setting.key_path_spending = true;
  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(key_path_spending, wrong_signature) {
  init_input();
  g_setting.flags = 6;
  g_setting.key_path_spending = true;
  g_setting.wrong_signature = true;
  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_SCHNORR, r);
}

UTEST(key_path_spending, wrong_pubkey_hash) {
  init_input();
  g_setting.flags = 6;
  g_setting.key_path_spending = true;
  g_setting.wrong_pubkey_hash = true;
  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_IDENTITY_PUBKEY_BLAKE160_HASH, r);
}

UTEST(script_path_spending, success) {
  init_input();
  g_setting.flags = 6;
  g_setting.script_path_spending = true;
  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(script_path_spending, wrong_pubkey) {
  init_input();
  g_setting.flags = 6;
  g_setting.script_path_spending = true;
  g_setting.wrong_pubkey_hash = true;
  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_MISMATCHED, r);
}

UTEST_MAIN();
