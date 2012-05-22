#!/bin/bash

TEST_DIR=tests
MKEY=${TEST_DIR}/mkey 
KEY_DIR=${TEST_DIR}/keys
PREFIX="/vkey/test"

# self sign test root key
$MKEY -i test_root -a vkey -f ${KEY_DIR}/root.pem -k ${KEY_DIR}/root_keystore -u ${PREFIX}/root -p ${PREFIX}/root -x 1

# sign test site key using root key
$MKEY -i test_site -a vkey -f ${KEY_DIR}/site.pem -k ${KEY_DIR}/root_keystore -u ${PREFIX}/root -p ${PREFIX}/site -x 1

# sign test node key using site key
$MKEY -i test_node -a vkey -f ${KEY_DIR}/node.pem -k ${KEY_DIR}/site_keystore -u ${PREFIX}/site -p ${PREFIX}/node -x 1

# publish something using test node key; here we use node key to sign itself
$MKEY -i test_content -a vkey -f ${KEY_DIR}/node.pem -k ${KEY_DIR}/node_keystore -u ${PREFIX}/node -p ${PREFIX}/content -x 1


