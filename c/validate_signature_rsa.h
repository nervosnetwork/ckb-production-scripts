#ifndef CKB_MISCELLANEOUS_SCRIPTS_RSA_ALL_H
#define CKB_MISCELLANEOUS_SCRIPTS_RSA_ALL_H

#include <stddef.h>

// used as algorithm_id, see below
// when algorithm_id is CKB_VERIFY_RSA, use RsaInfo structure
#define CKB_VERIFY_RSA 1
// when algorithm_id is CKB_VERIFY_ISO9796_2, use RsaInfo structure
#define CKB_VERIFY_ISO9796_2 2

// used as key_size enum values: their "KeySize" are 1024, 2048, 4098 bits.
// The term "KeySize" has same meaning below.
#define CKB_KEYSIZE_1024 1
#define CKB_KEYSIZE_2048 2
#define CKB_KEYSIZE_4096 3

// used as padding value
// PKCS# 1.5
#define CKB_PKCS_15 0
// PKCS# 2.1
#define CKB_PKCS_21 1

// used as md_type value (message digest), it has same value as
// mbedtls_md_type_t
#define CKB_MD_NONE 0
// very weak hash function
//#define CKB_MD_MD2 1       /**< The MD2 message digest. */
//#define CKB_MD_MD4 2       /**< The MD4 message digest. */
//#define CKB_MD_MD5 3       /**< The MD5 message digest. */
// SHA1 is weak too, but it's already used by ISO 9796-2
// It's not allowed to set SHA1 while using RSA
#define CKB_MD_SHA1 4   /**< The SHA-1 message digest. */
#define CKB_MD_SHA224 5 /**< The SHA-224 message digest. */
#define CKB_MD_SHA256 6 /**< The SHA-256 message digest. */
#define CKB_MD_SHA384 7 /**< The SHA-384 message digest. */
#define CKB_MD_SHA512 8 /**< The SHA-512 message digest. */
// #define CKB_MD_RIPEMD160 9 /**< The RIPEMD-160 message digest. */

#define PLACEHOLDER_SIZE (128)

/** signature (in witness, or passed as arguments) memory layout
 * This structure contains the following information:
 * 1) Common header, 4 bytes, see RsaInfo
 * 2) RSA Public Key
 * 3) RSA Signature data
 *
-----------------------------------------------------------------------------
|common header| E |  N (KeySize/8 bytes) | RSA Signature (KeySize/8 bytes)|
-----------------------------------------------------------------------------
The common header, E both occupy 4 bytes. E is in little endian(uint32_t).
So the total length in byte is: 4 + 4 + KeySize/8 + KeySize/8.

The public key hash is calculated by: blake160(common header + E + N), Note: RSA
signature part is dropped. Here function blake160 returns the first 20 bytes of
blake2b result.
*/
typedef struct RsaInfo {
  // common header part, 4 bytes
  // if it doesn't take 4 bytes in memory, ERROR_BAD_MEMORY_LAYOUT returned
  // from validate_signature
  uint8_t algorithm_id;
  uint8_t key_size;
  uint8_t padding;
  uint8_t md_type;

  // RSA public key, part E. It's normally very small, OK to use uint32_to hold
  // it. https://eprint.iacr.org/2008/510.pdf The choice e = 65537 = 2^16 + 1 is
  // especially widespread. Of the certificates observed in the UCSD TLS Corpus
  // [23] (which was obtained by surveying frequently-used TLS servers), 99.5%
  // had e = 65537, and all had e at most 32 bits.
  uint32_t E;

  // The following parts are with variable length. We give it a placeholder.
  // The real length are both KeySize/8.

  // RSA public key, part N.
  // The public key is the combination of E and N.
  // But N is a very large number and need to use array to represent it.
  // The total length in byte is (KeySize)/8.
  // The memory layout is the same as the field "p" of mbedtls_mpi type.
  uint8_t N[PLACEHOLDER_SIZE];

  // pointer to RSA signature
  uint8_t sig[PLACEHOLDER_SIZE];
} RsaInfo;

/**
 * get offset of signature based on key size.
 */
uint8_t *get_rsa_signature(RsaInfo *info);
/**
 * get total length of RsaInfo based on key size.
 */
uint32_t calculate_rsa_info_length(int key_size);

/*
 * get real "KeySize" in bits according to the CKB_KEYSIZE_1024,
 * CKB_KEYSIZE_2048 and CKB_KEYSIZE_4096
 */
uint32_t get_key_size(uint8_t key_size_enum);

/**
 *
 * @param prefilled_data ignore. Not used.
 * @param signature_buffer pointer to signature buffer. It is casted to type
 * "RsaInfo*"
 * @param signature_size size of signature_buffer.
 * @param message_buffer pointer to message buffer.
 * @param message_size size of message_buffer.
 * @param output ignore. Not used
 * @param output_len ignore. Not used.
 * @return 0 succeed; otherwise fail.
 */
int validate_signature(void *prefilled_data, const uint8_t *signature_buffer,
                       size_t signature_size, const uint8_t *msg_buf,
                       size_t msg_size, uint8_t *output, size_t *output_len);

/**
 * Note: there is no prefilled data for RSA.
 * Always succeed.
 * @param data not used.
 * @param len not used.
 * @return always succeed.
 */
int load_prefilled_data(void *data, size_t *len);

#endif  // CKB_MISCELLANEOUS_SCRIPTS_RSA_ALL_H
