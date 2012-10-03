#!/bin/bash

# initialize db if not exist
if [ -z "$KEY_DB_FILE" ]
then
	DB_FILE="$HOME/.ccnx/.vkey.db"
else
	DB_FILE="$KEY_DB_FILE"
fi

sqlite3 $DB_FILE "create table if not exists trusted_keys(name TEXT, key BLOB, keysize INTEGER, timestamp INTEGER, freshness INTEGER);"

# set the root key digest
cp .vkey_root_hash $HOME/.ccnx/.vkey_root_hash
