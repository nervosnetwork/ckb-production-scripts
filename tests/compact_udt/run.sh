#!/bin/bash

CUR_PWD=$(pwd)
CUR_DIR=$(cd `dirname $0`; pwd)
FOLDER=build-debug

rm -rf $CUR_DIR/$FOLDER
mkdir -p $CUR_DIR/$FOLDER
cd $CUR_DIR/$FOLDER

cmake -G "Unix Makefiles" ../
if (( $? == 0 ))
then
    echo "succcess"
else
    exit 1
fi

make all
if (( $? == 0 ))
then
    echo "succcess"
else
    exit 1
fi

./cudt_simulator
if (( $? == 0 ))
then
    echo "succcess"
else
    exit 1
fi

cd $CUR_PWD
