
#
# This script is compatible with Capsule.
#

# Before you run this script, make sure the following are done:
# 1. install ckb-binary-patcher
#    cargo install --git https://github.com/xxuejie/ckb-binary-patcher.git
# 2. install Rust nightly toolchain
#    rustup toolchain install nightly-2020-09-28
# 3. if you want to use this script to your own project, don't forget to copy the following files
#    * contracts/validate-signature-rsa/rust-toolchain
#    * contracts/validate-signature-rsa/.cargo/config
#    They make contracts built with nightly tool chain and proper options.

set -e
BIN=./target/riscv64imac-unknown-none-elf/debug/validate-signature-rsa

cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p build/debug

cd contracts/validate-signature-rsa

echo "cargo build the contract ..."
cargo build --target riscv64imac-unknown-none-elf
cd ../../

echo "patch the binary ..."
ckb-binary-patcher -i ${BIN} -o ${BIN}

echo "copy the binary to build folder ..."
cp ${BIN} ./build/debug/validate-signature-rsa

echo "build contract done!"
echo "trying 'cargo test -p tests' to run tests."
