
set -e
FOLDER=simulator-build-debug
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p ${FOLDER}
cd ${FOLDER}
cmake -DCMAKE_C_COMPILER=clang ..
make all
cd ../../..
echo "Running tests"
tests/taproot_lock/${FOLDER}/taproot_lock_simulator
echo "Done"
