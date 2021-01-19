#ifndef CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H
#define CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H

#include <stddef.h>

// used as algorithm_id, see below
// when algorithm id is CKB_VERIFY_RSA, use RsaInfo structure
#define CKB_VERIFY_RSA 1
// when algorithm id is CKB_VERIFY_SECP256R1, use Secp256r1Info structure
#define CKB_VERIFY_SECP256R1 2
// when algorithm id is CKB_VERIFY_ISO9796_2, use RsaInfo structure
#define CKB_VERIFY_ISO9796_2 3
// not supported yet
#define CKB_VERIFY_SECP256R1_RECOVERABLE 0xFF

#define PLACEHOLDER_SIZE (128)

/** signature(in witness) memory layout
 * This structure contains the following information:
 * 1) RSA Key Size
 * 2) RSA Public Key
 * 3) RSA Signature data
 *
---------------------------------------------------------------------------
| key_size | E |  N (key_size/8 bytes) | RSA Signature (key_size/8 bytes) |
---------------------------------------------------------------------------
The key_size, E both occupy 4 bytes, in little endian (uint32_t).
So the total length in byte is: 4 + 4 + key_size/8 + key_size/8.

The public key hash is calculated by: blake160(key_size + E + N), Note: RSA
signature part is dropped. Here function blake160 returns the first 20 bytes of
blake2b result.
*/
typedef struct RsaInfo {
  uint32_t algorithm_id;  // common header part

  // RSA Key Size, in bits. For example, 1024, 2048, 4096
  uint32_t key_size;
  // RSA public key, part E. It's normally very small, OK to use uint32_to hold
  // it. https://eprint.iacr.org/2008/510.pdf The choice e = 65537 = 2^16 + 1 is
  // especially widespread. Of the certificates observed in the UCSD TLS Corpus
  // [23] (which was obtained by surveying frequently-used TLS servers), 99.5%
  // had e = 65537, and all had e at most 32 bits.
  uint32_t E;

  // The following parts are with variable length. We give it a placeholder.
  // The real length are both key_size/8.

  // RSA public key, part N.
  // The public key is the combination of E and N.
  // But N is a very large number and need to use array to represent it.
  // The total length in byte is key_size/8 (The key_size is in bits).
  // The memory layout is the same as the field "p" of mbedtls_mpi type.
  uint8_t N[PLACEHOLDER_SIZE];

  // pointer to RSA signature
  uint8_t sig[PLACEHOLDER_SIZE];
} RsaInfo;

#define SECP256R1_PUBLIC_KEY_SIZE 64
#define SECP256R1_SIG_SIZE 64

typedef struct Secp256r1Info {
  uint32_t algorithm_id;  // common header part
  // X: 32 bytes
  // Y: 32 bytes
  // X, Y are in Jacobian coordinates, see: mbedtls_ecp_point
  uint8_t public_key[SECP256R1_PUBLIC_KEY_SIZE];
  // r: 32 bytes
  // s: 32 bytes
  uint8_t sig[SECP256R1_SIG_SIZE];
} Secp256r1Info;

/**
 * get offset of signature based on key size.
 */
uint8_t* get_rsa_signature(RsaInfo* info);
/**
 * get total length of RsaInfo based on key size.
 */
uint32_t calculate_rsa_info_length(int key_size);
#endif  // CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H
