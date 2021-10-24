#ifndef CKB_C_JOII_DEBUG_H_
#define CKB_C_JOII_DEBUG_H_

//#ifdef DEBUG_CKB
//#define CKB_C_STDLIB_PRINTF
//#include "debug.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef CKB_C_STDLIB_PRINTF
#define CKB_C_STDLIB_PRINTF_BUFFER_SIZE 1024
#endif  // CKB_C_STDLIB_PRINTF

inline uint64_t PtrToNum(const void* p) {
  uint64_t r = 0;
  memcpy(&r, &p, 8);
  return r;
}

inline void PrintMem(const uint8_t* ptr, int size, const char* buf_name) {
  if (buf_name) {
    printf("%s, addr:0x%lX, size:%d\n", buf_name, PtrToNum(ptr), size);
  }
  if (ptr == NULL) {
    printf("this val is NULL\n");
    return;
  }
  for (int i = 0; i < size; i++) {
    printf("0x%02X, ", ptr[i]);
    if (i % 16 == 15)
      printf("\n");
  }
  printf("\n");
}

#define PRINT_MEM(v) PrintMem((const uint8_t*)v, sizeof(v), #v)
#define PRINT_MEM2(v, s) PrintMem((const uint8_t*)v, s, #v)
#define PRINT_INT(i) printf("val %s is: %ld\n", #i, (int64_t)i)
#define PRINTF(fmt, arg...) printf(fmt, ##arg)
//#else   // DEBUG_CKB
//#define PRINT_MEM(v)
//#define PRINT_MEM2(v, s)
//#define PRINT_INT(i)
//#define PRINTF(fmt, arg...)
//#endif  // DEBUG_CKB

#endif  // CKB_C_JOII_DEBUG_H_
