
set -e
FOLDER=simulator-build-debug
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p ${FOLDER}
cd ${FOLDER}
cmake -DCMAKE_C_COMPILER=clang ..
make all
cd ../../..
echo "Running tests"
tests/omni_lock/${FOLDER}/omni_lock_simulator
echo "Done"
