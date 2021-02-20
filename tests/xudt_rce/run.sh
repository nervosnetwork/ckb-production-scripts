
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p cmake-build-debug
cd cmake-build-debug
cmake -DCMAKE_C_COMPILER=clang ..
make all
cd ../../..
echo "Running tests"
tests/xudt_rce/cmake-build-debug/xudt_rce_simulator
echo "Done"
