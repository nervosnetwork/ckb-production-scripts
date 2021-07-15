# Testing Results for validate_signature_rsa

Following [ckb-contract-guidelines](https://github.com/nervosnetwork/ckb-contract-guidelines)


### Rule 1: 100% test coverage
Uncomment the following in CMakeLists.txt to enable:
```text
# uncomment it for coverage test
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
#add_definitions(-DCKB_COVERAGE)
```
Then use ```tests/validate_signature_rsa/run.sh``` to run the whole test case and get coverage results.

Every branch is covered as much as possible, see "iso97962_error_cases_test", 
"validate_signature_error_cases_test" in "tests/validate_signature_rsa/validate_signature_rsa_sim.c".
They're created to cover corner cases.

The final results is 92%. The code is not fully covered by test case due to some reasons:
1. Already checked condition makes some code unreachable, for example, the following ASSERT(false)
is unreachable due to being checked before use.
```C
  if (key_size_enum == CKB_KEYSIZE_1024) {
    return 1024;
  } else if (key_size_enum == CKB_KEYSIZE_2048) {
    return 2048;
  } else if (key_size_enum == CKB_KEYSIZE_4096) {
    return 4096;
  } else {
    ASSERT(false);
    return 0;
  }
}
```

Comments are added on some place for this reason.

2. We can't cover full ISO 9796-2 cases due to not enough data.
It happens in ```get_trailer_by_md```: we now only use SHA1.

### Rule 2: Multiple execution environment for tests

#### Normal CKB-VM as used in CKB
```bash
run tests/validate_signature_rsa/run-in-vm.sh
```

#### At least 20 runs of CKB-VM running in chaos mode
Rebuild ckb-vm with
```text
cargo build --release --features "enable-chaos-mode-by-default"
```
And then run:
```bash
run tests/validate_signature_rsa/run-in-vm.sh
```


#### Native x64 environment for gathering test coverage
See rule 1.

#### LLVM Undefined Behavior Sanitizer
See below.

#### LLVM Address Sanitizer
Uncomment the following in CMakeLists.txt to enable:
```
# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")
```

There 2 issues detected: 

1. An overflow issue is detected and it's intended:

```C
uint8_t *get_rsa_signature(RsaInfo *info) {
  int length = get_key_size(info->key_size) / 8;
  // note: sanitizer reports error:
  // Index 256 out of bounds for type 'uint8_t [128]'
  // It's intended. RsaInfo is actually an variable length buffer.
  return (uint8_t *)&info->N[length];
}
```

2. The warning from mbedtls:
```text
Load of misaligned address 0x7ffee94dd25c for type 'size_t' (aka 'unsigned long'), which requires 8 byte alignment
```
It happens in memory allocation in mbedtls source code. It's difficult to change.

### Fuzzing test on ckb_dlopen2
This work is contributed by Trail of Bits. It only works for "ckb_dlfcn.h", mainly for the function "ckb_dlopen2".

```bash
make
./dlopen_fuzzer -workers=40 -jobs=40 corpus
```
adjust "40" to CPU cores of your machine. It's great to put some dynamic library files in "corpus" folder first:
```bash
cp ../../build/always_success corpus/
cp ../../build/validate_signature_rsa corpus/
```

Get code coverage by:
```bash
make report
make show
```

#### heap-buffer-overflow at "context->dynstr + sym->st_name"
This issue is resolved by post-checking.
```C
    // here the fuzzer reports "heap-buffer-overflow" issue
    // we will check "str" in range next
    const char *str = context->dynstr + sym->st_name;
    // issue:
    // 9. Possible out-of-bounds read in ckb_dlsym
    if (!check_in_range(str, context)) {
      return 0;
    }
```

