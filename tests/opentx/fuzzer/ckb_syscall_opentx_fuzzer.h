#ifndef __SYSCALL_OPENTX_FUZZER_H__
#define __SYSCALL_OPENTX_FUZZER_H__

#define MIN(a, b) ((a) < (b) ? (a) : (b))

uint8_t g_data[256] = {0};

uint8_t g_script[] = {
    0x38, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
    0x31, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x03, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56};

uint8_t g_out_point[36] = {0};

long __internal_syscall(long n, long a0, long a1, long a2, long a3, long a4,
                        long a5) {
  uint64_t* addr = (uint64_t*)a0;
  uint64_t* len = (uint64_t*)a1;
  size_t offset = (size_t)a2;
  size_t index = (size_t)a3;
  size_t source = (size_t)a4;
  size_t field = (size_t)a5;

  // https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0009-vm-syscalls/0009-vm-syscalls.md#partial-loading
  const uint8_t* data = g_data;
  size_t data_length = sizeof(g_data);
  size_t size = *len;

  if (field == CKB_CELL_FIELD_CAPACITY) {
    data = g_data;
    data_length = 16;
    if (index > 9) {
      return 1;
    }
  } else if (field == CKB_CELL_FIELD_TYPE || field == CKB_CELL_FIELD_LOCK) {
    data = g_script;
    data_length = sizeof(g_script);
  }

  // fields conflict.
  if (field == CKB_INPUT_FIELD_OUT_POINT && n == SYS_ckb_load_input_by_field) {
    data = g_out_point;
    data_length = sizeof(g_out_point);
  }
  size_t full_size = data_length - offset;
  size_t real_size = MIN(size, full_size);
  if (addr != NULL) {
    memcpy(addr, data + offset, real_size);
  }
  *len = full_size;
  return 0;
}

#define syscall(n, a, b, c, d, e, f)                                           \
  __internal_syscall(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
                     (long)(f))

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  return syscall(0, addr, len, offset, index, source, field);
}

int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field) {
  return syscall(0, addr, len, offset, index, source, field);
}

int ckb_checked_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                                    size_t index, size_t source, size_t field) {
  return syscall(SYS_ckb_load_input_by_field, addr, len, offset, index, source,
                 field);
}

int ckb_exit(int8_t code) { return 0; }

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  return syscall(0, addr, len, offset, 0, 0, 0);
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  return syscall(0, addr, len, offset, 0, 0, 0);
}

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source) {
  return syscall(0, addr, len, offset, index, source, 0);
}

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source) {
  return syscall(0, addr, len, offset, index, source, 0);
}

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source) {
  return syscall(0, addr, len, offset, index, source, 0);
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  return syscall(0, addr, len, offset, index, source, 0);
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  return syscall(0, addr, len, offset, 0, 0, 0);
}

int ckb_load_transaction(void* addr, uint64_t* len, size_t offset) {
  return syscall(0, addr, len, offset, 0, 0, 0);
}

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field) {
  return syscall(0, addr, len, offset, index, source, field);
}

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
  return syscall(0, addr, len, offset, index, source, field);
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  return syscall(0, addr, len, offset, index, source, 0);
}

int ckb_debug(const char* s) { return 0; }

#endif
