#if defined(CKB_COVERAGE)
#define ASSERT(s) (void)0
#else
#include <assert.h>
#define ASSERT(s) assert(s)
#endif

#include "cardano_lock.c"
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

UTEST(test1, sign_and_verify) {
  unsigned char public_key[32], private_key[64], seed[32];
  unsigned char signature[64];

  const unsigned char message[] = "Hello, world!";
  const int message_len = sizeof(message) - 1;

  /* create a random seed, and a keypair out of that seed */
  //  ed25519_create_seed(seed);
  ed25519_create_keypair(public_key, private_key, seed);

  /* create signature on the message with the keypair */
  ed25519_sign(signature, message, message_len, public_key, private_key);

  /* verify the signature */
  //  err = ed25519_verify(signature, message, message_len, public_key);
  int success = ed25519_verify(signature, message, message_len, public_key);
  ASSERT_EQ(success, 1);
}

UTEST(test2, sign_and_verify) {
  // This case is used to test conformance
  // https://github.com/Emurgo/message-signing/blob/master/examples/rust/src/main.rs
  const char payload[] = "message to sign";
  const char external_aad[] = "externally supplied data not in sign object";

  size_t sign_msg_len = 0;
  int err = cardano_convert_copy(
      NULL, &sign_msg_len, (uint8_t*)payload, (uint32_t)(sizeof(payload) - 1),
      (uint8_t*)external_aad, (uint32_t)(sizeof(external_aad) - 1));
  // ASSERT_EQ(err, 0);
  ASSERT(sign_msg_len > 0);

  uint8_t sign_msg[sign_msg_len];
  memset(sign_msg, 0, sign_msg_len);
  err = cardano_convert_copy(sign_msg, &sign_msg_len, (uint8_t*)payload,
                             (uint32_t)(sizeof(payload) - 1),
                             (uint8_t*)external_aad,
                             (uint32_t)(sizeof(external_aad) - 1));
  ASSERT_EQ(err, 0);
  ASSERT_EQ(sizeof(sign_msg), sign_msg_len);

  const uint8_t check_sign_msg[] = {
      0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65,
      0x31, 0x40, 0x58, 0x2B, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6E, 0x61,
      0x6C, 0x6C, 0x79, 0x20, 0x73, 0x75, 0x70, 0x70, 0x6C, 0x69, 0x65,
      0x64, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x6E, 0x6F, 0x74, 0x20,
      0x69, 0x6E, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x20, 0x6F, 0x62, 0x6A,
      0x65, 0x63, 0x74, 0x4F, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
      0x20, 0x74, 0x6F, 0x20, 0x73, 0x69, 0x67, 0x6E};
  ASSERT_EQ(sign_msg_len, sizeof(check_sign_msg));
  ASSERT_EQ(memcmp(check_sign_msg, sign_msg, sign_msg_len), 0);

  unsigned char public_key[32] = {0}, private_key[64] = {0};
  unsigned char seed[32] = {
      34, 125, 55,  10,  222, 244, 31,  91,  181, 231, 62,
      80, 90,  53,  246, 160, 226, 111, 123, 228, 188, 90,
      15, 130, 210, 206, 78,  199, 209, 18,  202, 234,
  };
  unsigned char signature[64] = {0};

  ed25519_create_keypair(public_key, private_key, seed);
  ed25519_sign(signature, sign_msg, sign_msg_len, public_key, private_key);

  uint8_t check_signed[] = {
      0x0E, 0xBF, 0x10, 0x47, 0x44, 0xD3, 0x15, 0x34, 0x45, 0x99, 0xCE,
      0x39, 0x47, 0x06, 0x0C, 0xA1, 0xD0, 0xFC, 0x19, 0x44, 0xCA, 0xB4,
      0xF1, 0xE3, 0xB3, 0xF7, 0xB5, 0x57, 0xB5, 0xCA, 0x0F, 0x12, 0xFC,
      0xA4, 0x9E, 0x4E, 0x3E, 0xB8, 0x95, 0xED, 0xFD, 0x1A, 0x89, 0x7C,
      0xA2, 0x24, 0x9C, 0x09, 0x1F, 0xCC, 0xDD, 0xE4, 0x63, 0xB0, 0xE6,
      0x7B, 0x2C, 0xC9, 0x28, 0x0A, 0xC0, 0x38, 0x60, 0x0D};

  ASSERT_EQ(memcmp(check_signed, signature, sizeof(signature)), 0);

  ASSERT_EQ(ed25519_verify(signature, sign_msg, sign_msg_len, public_key), 1);
}

UTEST(test, dev) {
  uint8_t payload[] = {
      0x77, 0x41, 0x72, 0xd0, 0xe1, 0xa7, 0x29, 0xe7, 0x87, 0x1a, 0x23,
      0xd9, 0x0a, 0xaa, 0x5f, 0x86, 0xc4, 0xbe, 0x0e, 0x00, 0x88, 0xe0,
      0x18, 0xb1, 0x99, 0x31, 0x7a, 0x60, 0xdd, 0x44, 0x71, 0x69,
  };

  uint8_t new_msg[128] = {0};
  size_t new_msg_len = sizeof(new_msg);
  int err = cardano_convert_copy(new_msg, &new_msg_len, payload,
                                 sizeof(payload), NULL, 0);
  ASSERT_EQ(err, CKB_SUCCESS);

  uint8_t seed[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  unsigned char public_key[32] = {0}, private_key[64] = {0};
  ed25519_create_keypair(public_key, private_key, seed);

  unsigned char signature[64] = {0};
  ed25519_sign(signature, new_msg, new_msg_len, public_key, private_key);

  blake2b_state b2b = {0};
  blake2b_init(&b2b, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&b2b, public_key, sizeof(public_key));
  uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
  blake2b_final(&b2b, pubkey_hash, BLAKE2B_BLOCK_SIZE);

  set_witness(public_key, signature);
  set_scritp(pubkey_hash);

  int rc_code = simulator_main();
  ASSERT_EQ(rc_code, 0);
}

UTEST_MAIN();
