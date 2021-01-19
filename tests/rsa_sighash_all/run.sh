set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p build.simulator
cd build.simulator
cmake -DCMAKE_C_COMPILER=clang ../../..
make all
../build.simulator/rsa_sighash_all
