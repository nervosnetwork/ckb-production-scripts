
#include "ckb_syscall_auth_sim.h"

#include "compact_udt_lock.h"

#include <stdbool.h>
#include <stdint.h>



int ckb_exec_cell(const uint8_t* code_hash,
                  uint8_t hash_type,
                  uint32_t offset,
                  uint32_t length,
                  int argc,
                  const char* argv[]) {
  ASSERT_DBG(false);
  return 0;
}
int ckb_dlopen2(const uint8_t* dep_cell_hash,
                uint8_t hash_type,
                uint8_t* aligned_addr,
                size_t aligned_size,
                void** handle,
                size_t* consumed_size) {
  ASSERT_DBG(false);
  return 0;
}
void* ckb_dlsym(void* handle, const char* symbol) {
  ASSERT_DBG(false);
  return NULL;
}
