
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
(cd ../../../deps/mbedtls && git apply --ignore-space-change ../../deps/bignum.c.patch || echo "applying patch, ignore error above.")
mkdir -p cmake-build-debug
cd cmake-build-debug
export CC=clang
export CXX=clang
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug ../../../..
make rsa_fuzzer
make rsa_coverage
cd ..
mkdir -p corpus
mkdir -p coverage
cmake-build-debug/rsa_fuzzer -workers=${NPROC:-4} -jobs=${NPROC:-4} corpus
