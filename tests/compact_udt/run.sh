#!/bin/bash

CUR_PWD=$(pwd)
CUR_DIR=$(cd `dirname $0`; pwd)
FOLDER=build-debug

rm -rf $CUR_DIR/$FOLDER
mkdir -p $CUR_DIR/$FOLDER
cd $CUR_DIR/$FOLDER

cmake -G "Unix Makefiles" ../
make all
./cudt_simulator
cd $CUR_PWD
