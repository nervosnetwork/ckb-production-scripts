#!/bin/bash

CUR_PWD=$(pwd)
CUR_DIR=$(cd `dirname $0`; pwd)
cd $CUR_DIR

rm -rf build_dbg
rm -f init.info
rm -f final.info

mkdir build_dbg
cd build_dbg

cmake -G "Unix Makefiles" ../ -DEnableGCC=Enable -DEnableCoverage=Enable

make all

lcov -c -i -d ./ -o init.info

./cudt_simulator

lcov -c -d ./ -o cover.info
lcov -a init.info -a cover.info -o total.info
lcov --remove total.info '*/usr/include/*' '*/usr/lib/*' '*/usr/lib64/*' '*/usr/local/include/*' '*/usr/local/lib/*' '*/usr/local/lib64/*' '*/third/*' 'testa.cpp' -o final.info
genhtml -o cover_report --legend --title "lcov"  --prefix=./ final.info

