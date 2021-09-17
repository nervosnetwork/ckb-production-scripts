
set -e
FOLDER=simulator-build-debug
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p ${FOLDER}
cd ${FOLDER}
cmake ..
make all
cd ../../..
echo "Running tests"
tests/auth/${FOLDER}/auth_simulator
echo "Done"
