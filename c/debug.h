#ifndef CKB_C_JOII_DEBUG_H_
#define CKB_C_JOII_DEBUG_H_

#ifdef CKB_C_STDLIB_PRINTF

#include <stdint.h>
#include <stdio.h>

void PrintMem(const uint8_t* ptr, int size, const char *buf_name) {
  if (buf_name) {
    printf("%s, addr:0x%X, size:%d\n", buf_name, (uint64_t)ptr, size);
  }
  if (ptr == NULL) {
    printf("this val is NULL\n");
    return;
  }
  for (int i = 0; i < size; i++) {
    printf("0x%02X, ", ptr[i]);
    if (i % 8 == 7)
      printf("\n");
  }
  printf("\n");
}
#else // CKB_C_STDLIB_PRINTF
void PrintMem(const uint8_t* ptr, int size, const char *buf_name) {}
#endif // CKB_C_STDLIB_PRINTF

#define PRINT_MEM(v) PrintMem((const uint8_t*)v, sizeof(v), #v)

#endif // CKB_C_JOII_DEBUG_H_
