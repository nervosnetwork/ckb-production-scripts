// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF

#include <stdio.h>
#include <stdint.h>

#include "nanocbor.h"
#include "ed25519.h"

int sign_and_verify_once() {
  int err = 0;
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
  err = ed25519_verify(signature, message, message_len, public_key);

  if (err != 0)
    err = 0;
  else
    err = 1;
  return err;
}

int main() {
    return sign_and_verify_once();
}
