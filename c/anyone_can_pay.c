/* UDT anyone-can-pay lock script
 * For simplify, we call a cell with anyone-can-pay lock a wallet cell.
 *
 * Wallet cell can be unlocked without a signature, if:
 *
 * 1. There is 1 output wallet cell that has the same type hash with the
 * unlocked wallet cell.
 * 2. The UDT or CKB(if type script is none) in the output wallet is more than
 * the unlocked wallet.
 * 3. if the type script is none, the cell data is empty.
 *
 * otherwise, the script perform secp256k1_blake160_sighash_all verification.
 */

#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "secp256k1_helper.h"
#include "secp256k1_lock.h"

#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_SIZE 32768
#define CKB_LEN 8
#define UDT_LEN 16
#define MAX_WITNESS_SIZE 32768
#define MAX_TYPE_HASH 256
#define MAX_POW_N 19
#define MAX_UINT64 0xffffffffffffffffUL
#define MAX_UINT128 (((uint128_t)MAX_UINT64 << 64) + MAX_UINT64)

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_OVERFLOWING -51
#define ERROR_OUTPUT_AMOUNT_NOT_ENOUGH -52
#define ERROR_TOO_MUCH_TYPE_HASH_INPUTS -53
#define ERROR_PARING_INPUT_FAILED -54
#define ERROR_PARING_OUTPUT_FAILED -55
#define ERROR_DUPLICATED_INPUT_TYPE_HASH -56
#define ERROR_DUPLICATED_OUTPUT_TYPE_HASH -57

typedef unsigned __int128 uint128_t;

typedef struct {
  int is_ckb_only;
  unsigned char type_hash[BLAKE2B_BLOCK_SIZE];
  uint64_t ckb_amount;
  uint128_t udt_amount;
  uint32_t output_cnt;
} InputWallet;

int quick_pow10(int n, uint64_t * result)
{
    static uint64_t pow10[MAX_POW_N + 1] = {
        1, 10, 100, 1000, 10000, 
        100000, 1000000, 10000000, 100000000, 1000000000,
        10000000000, 100000000000, 1000000000000, 10000000000000, 100000000000000,
        1000000000000000, 10000000000000000, 100000000000000000, 1000000000000000000, 10000000000000000000U,
    };

    if(n > MAX_POW_N) {
      return 1;
    }

    *result = pow10[n]; 
    return 0;
}

int uint64_overflow_add(uint64_t * result, uint64_t a, uint64_t b){
  if (MAX_UINT64 - a < b) {
    /* overflow */
    return 1;
  }
  *result = a + b;
  return 0;
}

int uint128_overflow_add(uint128_t * result, uint128_t a, uint128_t b){
  if (MAX_UINT128 - a < b) {
    /* overflow */
    return 1;
  }
  *result = a + b;
  return 0;
}


int check_payment_unlock(uint64_t min_ckb_amount, uint128_t min_udt_amount) {
  unsigned char lock_hash[BLAKE2B_BLOCK_SIZE];
  InputWallet input_wallets[MAX_TYPE_HASH];
  uint64_t len = BLAKE2B_BLOCK_SIZE;
  /* load wallet lock hash */
  int ret = ckb_load_script_hash(lock_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > BLAKE2B_BLOCK_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }

  /* iterate inputs and find input wallet cell */
  int i = 0;
  len = BLAKE2B_BLOCK_SIZE;
  while (1) {
    if (i >= MAX_TYPE_HASH) {
      return ERROR_TOO_MUCH_TYPE_HASH_INPUTS;
    }

    ret = ckb_checked_load_cell_by_field(input_wallets[i].type_hash, &len, 0, i,
                                         CKB_SOURCE_GROUP_INPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);

    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }

    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    input_wallets[i].is_ckb_only = ret == CKB_ITEM_MISSING;
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }

    /* load amount */
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field(
        (uint8_t *)&input_wallets[i].ckb_amount, &len, 0, i,
        CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len != CKB_LEN) {
      return ERROR_ENCODING;
    }
    len = UDT_LEN;
    ret = ckb_load_cell_data((uint8_t *)&input_wallets[i].udt_amount, &len, 0,
                             0, CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    if (input_wallets[i].is_ckb_only) {
      /* ckb only wallet should has no data */
      if (len != 0) {
        return ERROR_ENCODING;
      }
    } else {
      if (len != UDT_LEN) {
        return ERROR_ENCODING;
      }
    }

    i++;
  }

  int input_wallets_cnt = i;

  /* iterate outputs wallet cell */
  i = 0;
  while (1) {
    uint8_t output_lock_hash[BLAKE2B_BLOCK_SIZE];
    uint8_t output_type_hash[BLAKE2B_BLOCK_SIZE];
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    /* check lock hash */
    ret = ckb_checked_load_cell_by_field(output_lock_hash, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
    int has_same_lock =
        memcmp(output_lock_hash, lock_hash, BLAKE2B_BLOCK_SIZE) == 0;
    if (!has_same_lock) {
      i++;
      continue;
    }
    /* load type hash */
    len = BLAKE2B_BLOCK_SIZE;
    ret = ckb_checked_load_cell_by_field(output_type_hash, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
    int is_ckb_only = ret == CKB_ITEM_MISSING;

    /* load amount */
    uint64_t ckb_amount;
    uint128_t udt_amount;
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field((uint8_t *)&ckb_amount, &len, 0, i,
                                         CKB_SOURCE_GROUP_INPUT,
                                         CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len != CKB_LEN) {
      return ERROR_ENCODING;
    }
    len = UDT_LEN;
    ret = ckb_load_cell_data((uint8_t *)&udt_amount, &len, 0, 0,
                             CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    if (is_ckb_only) {
      /* ckb only wallet should has no data */
      if (len != 0) {
        return ERROR_ENCODING;
      }
    } else {
      if (len != UDT_LEN) {
        return ERROR_ENCODING;
      }
    }

    /* find input wallet which has same type hash */
    int found_inputs = 0;
    for (int j = 0; j < input_wallets_cnt; j++) {
      int has_same_type = 0;
      /* check type hash */
      if (is_ckb_only) {
        has_same_type = input_wallets[j].is_ckb_only;
      } else {
        has_same_type = memcmp(output_type_hash, input_wallets[j].type_hash,
                               BLAKE2B_BLOCK_SIZE) == 0;
      }
      if (!has_same_type) {
        continue;
      }
      /* compare amount */
      uint64_t min_output_ckb_amount;
      uint128_t min_output_udt_amount;
      int overflow;
      overflow = uint64_overflow_add(&min_output_ckb_amount, input_wallets[j].ckb_amount, min_ckb_amount);
      int invalid_output_ckb = overflow || ckb_amount < min_output_ckb_amount;
      overflow = uint128_overflow_add(&min_output_udt_amount, input_wallets[j].udt_amount, min_udt_amount);
      int invalid_output_udt = overflow || udt_amount < min_output_udt_amount;

      /* fail the unlock if both conditions can't satisfied */
      if(invalid_output_ckb && invalid_output_udt) {
        return ERROR_OUTPUT_AMOUNT_NOT_ENOUGH;
      }

      /* increase counter */
      found_inputs++;
      input_wallets[j].output_cnt += 1;
      if (found_inputs > 1) {
        return ERROR_DUPLICATED_INPUT_TYPE_HASH;
      }
      if (input_wallets[j].output_cnt > 1) {
        return ERROR_DUPLICATED_OUTPUT_TYPE_HASH;
      }
    }

    /* one output should pair with one input */
    if (found_inputs == 0) {
      return ERROR_PARING_OUTPUT_FAILED;
    } else if (found_inputs > 1) {
      return ERROR_DUPLICATED_INPUT_TYPE_HASH;
    }

    i++;
  }

  /* check inputs wallet, one input should pair with one output */
  for (int j = 0; j < input_wallets_cnt; j++) {
    if (input_wallets[j].output_cnt == 0) {
      return ERROR_PARING_INPUT_FAILED;
    } else if (input_wallets[j].output_cnt > 1) {
      return ERROR_DUPLICATED_OUTPUT_TYPE_HASH;
    }
  }

  return CKB_SUCCESS;
}

int has_signature(int *has_sig) {
  int ret;
  unsigned char temp[MAX_WITNESS_SIZE];

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);

  if ((ret == CKB_INDEX_OUT_OF_BOUND) || (ret == CKB_SUCCESS && witness_len == 0)) {
    *has_sig = 0;
    return CKB_SUCCESS;
  }

  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  *has_sig = lock_bytes_seg.size > 0;
  return CKB_SUCCESS;
}

int read_args(unsigned char *pubkey_hash, uint64_t *min_ckb_amount,
              uint128_t *min_udt_amount) {
  int ret;
  uint64_t len = 0;

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size < BLAKE160_SIZE ||
      args_bytes_seg.size > BLAKE160_SIZE + 2) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(pubkey_hash, args_bytes_seg.ptr, BLAKE160_SIZE);
  *min_ckb_amount = 0;
  *min_udt_amount = 0;
  if (args_bytes_seg.size > BLAKE160_SIZE) {
    int x = args_bytes_seg.ptr[BLAKE160_SIZE];
    int is_overflow = quick_pow10(x, min_ckb_amount);
    if (is_overflow) {
      *min_ckb_amount = MAX_UINT64;
    }
  }
  if (args_bytes_seg.size > BLAKE160_SIZE + 1) {
    int x = args_bytes_seg.ptr[BLAKE160_SIZE + 1];
    uint64_t amount;
    int is_overflow = quick_pow10(x, &amount);
    if(is_overflow) {
      *min_udt_amount = MAX_UINT64;
    } else {
      *min_udt_amount = amount;
    }
  }
  return CKB_SUCCESS;
}

int main() {
  int ret;
  int has_sig;
  unsigned char pubkey_hash[BLAKE160_SIZE];
  uint64_t min_ckb_amount;
  uint128_t min_udt_amount;
  ret = read_args(pubkey_hash, &min_ckb_amount, &min_udt_amount);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = has_signature(&has_sig);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (has_sig) {
    /* unlock via signature */
    return verify_secp256k1_blake160_sighash_all(pubkey_hash);
  } else {
    /* unlock via payment */
    return check_payment_unlock(min_ckb_amount, min_udt_amount);
  }
}
