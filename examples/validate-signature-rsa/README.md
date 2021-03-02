# Demo for validate_signature_rsa
This document describes how to use dynamic library "validate_signature_rsa" to write a lock script. 
It uses RSA instead of secp256k1. It's just a demo, don't use it without improvement for product directly.


## Build contract

```bash
make validate_signature_rsa-via-docker
```
then copy the binary to the target folder: 
```bash
cp build/validate_signature_rsa examples/validate-signature-rsa/dynamic-libray/
```
Do it only once.


## Build with Capsule 
You need to install [Capsule](https://github.com/nervosnetwork/capsule) first. 

Build contracts:

``` sh
cd examples/validate-signature-rsa
capsule build
```

Run tests:

``` sh
capsule test
```

## Build without capsule
Capsule use docker to build the contracts and run tests. Feel free to do it without it. 
Please read this script: ```examples/validate-signature-rsa/build-without-capsule.sh```
You need to install [GNU toolchain for RISC-V](https://github.com/nervosnetwork/ckb-riscv-gnu-toolchain) first. 
