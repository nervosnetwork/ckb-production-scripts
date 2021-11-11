#!/bin/bash

CUR_DIR=$(cd `dirname $0`; pwd)
TESTDATA_DIR=$CUR_DIR/../compact_udt_rust/test_data/

OUTPUT_H_FILE=$CUR_DIR/test_compact_udt_config.h

rm -rf $OUTPUT_H_FILE

echo "#ifndef _TESTS_COMPACT_UDT_TESTDATA_CONFIG_H_" >> $OUTPUT_H_FILE
echo "#define COMPACT_UDT_UNITTEST_SRC_PATH \"$TESTDATA_DIR\"" >> $OUTPUT_H_FILE
echo "#endif  // _TESTS_COMPACT_UDT_TESTDATA_CONFIG_H_" >> $OUTPUT_H_FILE
