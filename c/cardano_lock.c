// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF

#include <stdio.h>
#include <stdint.h>

#include "nanocbor.h"
#include "ed25519.h"

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main(int argc, const char* argv[]) {
#endif
  return 0;
}


