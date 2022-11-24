#include "dump.h"

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);

#include <stddef.h>
#include <stdint.h>

// in secp256k1_ctz64_var: we don't have __builtin_ctzl in gcc for RISC-V
#define __builtin_ctzl secp256k1_ctz64_var_debruijn

#include "ckb_swappable_signatures.h"
#include "ckb_syscalls.h"
#include "secp256k1_helper_20210801.h"
#include "validate_signature_rsa.h"

#include "blockchain.h"
#include "ckb_consts.h"
#include "ckb_identity.h"
// #include "xudt_rce_mol.h"

#define ERROR_UNREACHABLE -1;
#define ERROR_ARGUMENTS_LEN -2;
#define ERROR_PUBKEY_BLAKE160_HASH -3;

__attribute__((visibility("default"))) int validate(int _is_owner_mode,
                                                    size_t _extension_index,
                                                    const uint8_t *args,
                                                    size_t args_len) {
  printf("hello world\n");
  int ret = 0;
  // Read owner pk hash from args.
  if (args_len != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  hex_dump("args", (const void *)args, args_len, 0);

  // Read signature from witness.

  const size_t sig_size = 16;
  uint8_t sig[sig_size];

  hex_dump("sig", (const void *)sig, sig_size, 0);

  // Validate signature.
  ret = verify_sighash_all((uint8_t *)args, sig, sig_size,
                           validate_signature_secp256k1, _ckb_convert_copy);
  printf("verify sighash all result %d\n", ret);
  return 0;
  return ret;
}
