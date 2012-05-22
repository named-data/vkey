#!/bin/bash

TEST_DIR=tests
MKEY=${TEST_DIR}/mkey 
KEY_DIR=${TEST_DIR}/keys
PREFIX="/vkey/test"

# self sign test root
$MKEY -i test_root -a vkey -f ${KEY_DIR}/root.pem -k ${KEY_DIR}/root_keystore -u ${PREFIX}/root -p ${PREFIX}/root -x 1

# sign test site
$MKEY -i test_site -a vkey -f ${KEY_DIR}/site.pem -k ${KEY_DIR}/root_keystore -u ${PREFIX}/site -p ${PREFIX}/site -x 1

# sign test node
$MKEY -i test_node -a vkey -f ${KEY_DIR}/node.pem -k ${KEY_DIR}/site_keystore -u ${PREFIX}/node -p ${PREFIX}/node -x 1

