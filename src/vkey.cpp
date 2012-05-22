/*
 * Copyright (c) 2012 University of California, Los Angeles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 */

#include "vkey.hpp"
#include <cassert>
#ifdef _DEBUG
#include <iostream>
#endif

using namespace VKey;

static const int KEY_SIZE = 162;
#ifdef _DEBUG
static unsigned char root_key[KEY_SIZE] = {0x30,0x81,0x9f,0x30,0xd,0x6,0x9,0x2a,0x86,0x48,0x86,0xf7,0xd,0x1,0x1,0x1,0x5,0x0,0x3,0x81,0x8d,0x0,0x30,0x81,0x89,0x2,0x81,0x81,0x0,0xb6,0x1b,0x38,0x7a,0xc9,0x23,0x20,0x5c,0x38,0xec,0x85,0xfa,0xe2,0xb2,0xdd,0xd2,0x30,0x97,0x14,0x10,0xda,0x9e,0x82,0x4f,0x33,0x2,0xf2,0xd8,0xf7,0x3b,0xae,0x4c,0xcd,0x87,0xc1,0xe1,0x18,0x3,0x69,0x7c,0x94,0xbf,0xc8,0x55,0x27,0x8e,0xce,0xd1,0x67,0xce,0xdc,0x64,0x34,0x2b,0x10,0xa7,0xbf,0x2b,0x9d,0x24,0x29,0xd9,0x1f,0x9c,0xf5,0x3,0x79,0x98,0xfb,0x8d,0x83,0x4d,0x40,0x32,0x20,0x45,0xd3,0x56,0x45,0x5a,0xc,0xd4,0xd7,0x57,0xbc,0xce,0xbf,0x18,0xa1,0x96,0x44,0xd4,0x48,0x99,0xed,0x0,0xee,0x45,0x57,0xa6,0x96,0x34,0x5a,0x93,0xc3,0x57,0xa0,0x3a,0x15,0xa6,0x76,0xf5,0x70,0x3e,0xaa,0x95,0x0,0x57,0x45,0xbe,0xba,0xe,0x3b,0xb1,0x81,0xec,0xe5,0x59,0x2,0x3,0x1,0x0,0x1};

const char *root_key_name = "/vkey/test/root";
#else
static unsigned char root_key[KEY_SIZE] = {0x30,0x81,0x9f,0x30,0xd,0x6,0x9,0x2a,0x86,0x48,0x86,0xf7,0xd,0x1,0x1,0x1,0x5,0x0,0x3,0x81,0x8d,0x0,0x30,0x81,0x89,0x2,0x81,0x81,0x0,0xb6,0x1b,0x38,0x7a,0xc9,0x23,0x20,0x5c,0x38,0xec,0x85,0xfa,0xe2,0xb2,0xdd,0xd2,0x30,0x97,0x14,0x10,0xda,0x9e,0x82,0x4f,0x33,0x2,0xf2,0xd8,0xf7,0x3b,0xae,0x4c,0xcd,0x87,0xc1,0xe1,0x18,0x3,0x69,0x7c,0x94,0xbf,0xc8,0x55,0x27,0x8e,0xce,0xd1,0x67,0xce,0xdc,0x64,0x34,0x2b,0x10,0xa7,0xbf,0x2b,0x9d,0x24,0x29,0xd9,0x1f,0x9c,0xf5,0x3,0x79,0x98,0xfb,0x8d,0x83,0x4d,0x40,0x32,0x20,0x45,0xd3,0x56,0x45,0x5a,0xc,0xd4,0xd7,0x57,0xbc,0xce,0xbf,0x18,0xa1,0x96,0x44,0xd4,0x48,0x99,0xed,0x0,0xee,0x45,0x57,0xa6,0x96,0x34,0x5a,0x93,0xc3,0x57,0xa0,0x3a,0x15,0xa6,0x76,0xf5,0x70,0x3e,0xaa,0x95,0x0,0x57,0x45,0xbe,0xba,0xe,0x3b,0xb1,0x81,0xec,0xe5,0x59,0x2,0x3,0x1,0x0,0x1};
const char *root_key_name = "/ndn/keys/root";
#endif


SigVerifier *
SigVerifier::sigVerifier = NULL;


SigVerifier *
SigVerifier::getInstance() {
	// it's not thread-safe yet. Maybe no need to enforce thread_safety?
	if (sigVerifier == NULL) {
		sigVerifier = new SigVerifier();
	}
	return sigVerifier;
}

bool 
SigVerifier::verify(ccn_upcall_info *info) {
	return verify(info->content_ccnb, info->pco);
}

bool 
SigVerifier::verify(const unsigned char *ccnb, ccn_parsed_ContentObject *pco) {
	if (contain_key_name(ccnb, pco) < 0)
		return false;
	
	ccn_charbuf *keyName = get_key_name(ccnb, pco);
	std::string name = charbuf_to_string(keyName);
	std::cout << ">> Verifying: " << name << std::endl;

	CcnxKeyObjectPtr keyObjectPtr = lookupKey(name);
	
	if (keyObjectPtr != CcnxKeyObject::Null) {
		bool verified = false;
		ccn_pkey *pubkey = keyObjectPtr->getCcnPKey();
		if (pubkey != NULL) {
			verified = (ccn_verify_signature((unsigned char *) ccnb, pco->offset[CCN_PCO_E], pco, pubkey) == 1);
		}
		ccn_pubkey_free(pubkey);
		ccn_charbuf_destroy(&keyName);
		return verified;
	}
	
	ccn_charbuf_destroy(&keyName);
	return false;
}

SigVerifier::SigVerifier(): m_dbManager(new SqliteKeyDBManager){
	ccn_charbuf *rootKey = ccn_charbuf_create();
	ccn_charbuf_reserve(rootKey, KEY_SIZE);
	memcpy(rootKey->buf, root_key, KEY_SIZE);
	rootKey->length = KEY_SIZE;

	CcnxKeyObjectPtr ptr(new CcnxKeyObject(root_key_name, rootKey, time(NULL), 365));
	m_rootKeyObjectPtr = ptr;
}


void
SigVerifier::addKeyToKeyMap(const CcnxKeyObjectPtr keyObjectPtr) {
	m_keyMap.insert(std::make_pair(keyObjectPtr->getKeyName(), keyObjectPtr));
}

void
SigVerifier::addKeyToKeyDB(const CcnxKeyObjectPtr keyObjectPtr) {
	m_dbManager->update();
	m_dbManager->insert(keyObjectPtr);
}

void
SigVerifier::deleteKeyFromKeyMap(const std::string name) {
	m_keyMap.erase(name);
}

CcnxKeyObjectPtr
SigVerifier::lookupKeyInKeyMap(std::string name) {
	KeyMap::iterator it = m_keyMap.find(name);
	if (it == m_keyMap.end()) {
		return CcnxKeyObject::Null;
	}

	return it->second;
}

CcnxKeyObjectPtr
SigVerifier::lookupKeyInKeyDB(std::string name) {
	m_dbManager->update();
	return m_dbManager->query(name);
}

CcnxKeyObjectPtr
SigVerifier::lookupKeyInNetwork(const ccn_charbuf *keyName) {
	return CcnxOneTimeKeyFetcher::fetch(keyName);
}

CcnxKeyObjectPtr
SigVerifier::lookupKey(std::string name) {
	std::string rootPrefix = root_key_name;
	if (rootPrefix == name.substr(0, rootPrefix.length())){
		return m_rootKeyObjectPtr;
	}

	// check keymap first
	CcnxKeyObjectPtr keyObjectPtr = lookupKeyInKeyMap(name);
	if (keyObjectPtr != CcnxKeyObject::Null) {
		if (keyObjectPtr->expired()) {
			// get rid of expired key
			deleteKeyFromKeyMap(name);
		}
		else {
			return keyObjectPtr;
		}
	}
	
	// next check the keyDB
	keyObjectPtr = lookupKeyInKeyDB(name);
	if (keyObjectPtr != CcnxKeyObject::Null) {
		// no need to check whether expired or not
		// we did the cleaning before lookup in DB

		// store it to the cache so we don't need to check DB next time
		addKeyToKeyMap(keyObjectPtr);
		return keyObjectPtr;
	}

	// finally, try to fetch from the network
	ccn_charbuf *keyName = ccn_charbuf_create();
	ccn_name_from_uri(keyName, name.c_str());
	keyObjectPtr = lookupKeyInNetwork(keyName);
	if (keyObjectPtr != CcnxKeyObject::Null) {
		if (!keyObjectPtr->expired()) {
			// store it to DB and cache
			addKeyToKeyMap(keyObjectPtr);
			addKeyToKeyDB(keyObjectPtr);
			ccn_charbuf_destroy(&keyName);
			return keyObjectPtr;
		}
	}

	// could not find the key anywhere
	// or the fetched key expired
	ccn_charbuf_destroy(&keyName);
	return CcnxKeyObject::Null;
}

CcnxKeyObjectPtr
CcnxKeyObject::Null;

CcnxKeyObject::CcnxKeyObject(const std::string keyName, const ccn_charbuf *key, time_t timestamp, int freshness): m_keyName(keyName), m_timestamp(timestamp), m_freshness(freshness) {
	m_key = ccn_charbuf_dup(key);
}

CcnxKeyObject::~CcnxKeyObject() {
	if (m_key != NULL)
		ccn_charbuf_destroy(&m_key);
	
}

std::string
CcnxKeyObject::getKeyName() {
	return m_keyName;
}

ccn_charbuf *
CcnxKeyObject::getKey() {
	ccn_charbuf *temp = ccn_charbuf_dup(m_key);
	return temp;
}

bool 
CcnxKeyObject::expired() {
	time_t now = time(NULL);
	return (m_timestamp + m_freshness * 60 * 60 * 24 < now);
}

ccn_pkey *
CcnxKeyObject::getCcnPKey() {
	ccn_charbuf *temp = this->getKey();	
	ccn_pkey *ccnPKey = ccn_d2i_pubkey(temp->buf, temp->length);
	ccn_charbuf_destroy(&temp);
	return ccnPKey;
}

SqliteKeyDBManager::SqliteKeyDBManager() {
	char *dbLoc = NULL;
	dbLoc = std::getenv("DB_FILE");
	m_dbFile = (dbLoc != NULL) ? dbLoc : std::getenv("HOME");
	m_dbFile += "/.ccnx/.vkey.db";
	
#ifdef _DEBUG
	m_tableName = "test_keys";
#else
	m_tableName = "trusted_keys";
#endif 

	m_tableReady = false;
	if (sqlite3_open(m_dbFile.c_str(), &m_db) == SQLITE_OK) {
		std::string zSql = "create table if not exists " + m_tableName + "(name TEXT, key BLOB, timestamp INTEGER, valid_to INTEGER);";
		int rc = sqlite3_exec(m_db, zSql.c_str(), NULL, NULL, NULL);
		if (rc == SQLITE_OK) {
			m_tableReady = true;
		}
		sqlite3_close(m_db);
	}
	else {
		std::cerr<<"Failed to open sqlite3 database: " << m_dbFile<<std::endl;
	}
}

bool 
SqliteKeyDBManager::insert(const CcnxKeyObjectPtr keyObjectPtr) {
	if (!checkAndOpenDB())
		return false;

	sqlite3_stmt *stmt;	
	std::string zSql = "INSERT INTO " + m_tableName +" VALUES(?,?,?,?);";
	assert(sqlite3_prepare_v2(m_db, zSql.c_str(), -1, &stmt, NULL) == SQLITE_OK);
	std::string name = keyObjectPtr->getKeyName();
	ccn_charbuf *key = keyObjectPtr->getKey();
	assert(sqlite3_bind_text(stmt, 1, name.c_str(), name.length(), SQLITE_STATIC) == SQLITE_OK);
	assert(sqlite3_bind_blob(stmt, 2, key->buf, key->length, SQLITE_STATIC) == SQLITE_OK);
	int timestamp = keyObjectPtr->getTimestamp();
	int valid_to = timestamp + keyObjectPtr->getFreshness() * 60 * 60 * 24;
	assert(sqlite3_bind_int(stmt, 3, timestamp) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 4, valid_to) == SQLITE_OK);
	assert(sqlite3_step(stmt) ==SQLITE_DONE);
	sqlite3_finalize(stmt);
	sqlite3_close(m_db);

	ccn_charbuf_destroy(&key);
	return true;
}

const CcnxKeyObjectPtr 
SqliteKeyDBManager::query(const std::string keyName) {

	if (!checkAndOpenDB())
		return CcnxKeyObject::Null;


	sqlite3_stmt *stmt;	
	std::string zSql = "SELECT * FROM " + m_tableName + " WHERE name == ?;";
	assert(sqlite3_prepare_v2(m_db, zSql.c_str(), -1, &stmt, NULL) == SQLITE_OK);
	assert(sqlite3_bind_text(stmt, 1, keyName.c_str(), keyName.length(), SQLITE_STATIC) == SQLITE_OK);
	if (sqlite3_step(stmt) == SQLITE_ROW) {

		int size = sqlite3_column_bytes(stmt,1);
		ccn_charbuf *key = ccn_charbuf_create();
		ccn_charbuf_reserve(key, size);
		memcpy(key->buf, sqlite3_column_blob(stmt, 1), size);
		key->length = size;
		
		time_t timestamp = sqlite3_column_int(stmt, 2);
		int freshness = (sqlite3_column_int(stmt, 3) - timestamp) / (60 * 60 *24);
		CcnxKeyObjectPtr ptr (new CcnxKeyObject(keyName, key, timestamp, freshness));
		ccn_charbuf_destroy(&key);
		sqlite3_finalize(stmt);
		sqlite3_close(m_db);

		return ptr;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(m_db);
	return CcnxKeyObject::Null;
}

bool 
SqliteKeyDBManager::update() {
	if (!checkAndOpenDB())
		return false;

	time_t now = time(NULL);
	sqlite3_stmt *stmt;
	std::string zSql = "DELETE FROM " + m_tableName + " WHERE valid_to < ?;";
	assert(sqlite3_prepare_v2(m_db, zSql.c_str(), -1, &stmt, NULL) == SQLITE_OK);
	assert(sqlite3_bind_int(stmt, 1, (int) now) == SQLITE_OK);
	assert(sqlite3_step(stmt) == SQLITE_DONE);
	assert(sqlite3_finalize(stmt) == SQLITE_OK);
	sqlite3_close(m_db);
	
	return true;
}


bool 
SqliteKeyDBManager::checkAndOpenDB() {
	if (!m_tableReady)
		return false;
	
	if (sqlite3_open(m_dbFile.c_str(), &m_db) != SQLITE_OK){
		std::cerr<<"Failed to open sqlite3 database: " << m_dbFile<<std::endl;
		return false;
	}
	
	return true;
}

const CcnxKeyObjectPtr
CcnxOneTimeKeyFetcher::fetch(const ccn_charbuf *keyName) {
	ccn *h = ccn_create();
	if (ccn_connect(h, NULL) < 0)
		return CcnxKeyObject::Null;
	
	ccn_charbuf *name = ccn_charbuf_dup(keyName);
	ccn_charbuf *result = ccn_charbuf_create();
	ccn_parsed_ContentObject pco = {0};
	int get_flags = 0;
	// no need for ccnd to verify key
	get_flags |= CCN_GET_NOKEYWAIT;
	int counter = 0;
	while(ccn_get(h, name, NULL, 500, result, &pco, NULL, get_flags) < 0 && counter < 3) counter++;

	// didn't fetch the key object from network
	if (counter == 3) {
#ifdef _DEBUG
		std::cout <<"Could not fetch key object"<<std::endl;
#endif
		return CcnxKeyObject::Null;
	}

	// verify fetched key object
	SigVerifier *verifier = SigVerifier::getInstance();
	// the signature of the key object can not be verified
	if(!verifier->verify(result->buf, &pco)) {
#ifdef _DEBUG
		std::cout <<"Could not verify fetched key object"<<std::endl;
#endif
		return CcnxKeyObject::Null;
	}
	
	time_t timestamp = 0;
	if (get_timestamp_in_seconds(result, pco, &timestamp) < 0) {
#ifdef _DEBUG
		std::cout <<"key object expired"<<std::endl;
#endif
		return CcnxKeyObject::Null;
	}

	int freshness = 0;
	freshness = get_freshness_in_days(result, pco);

	const unsigned char *ptr = result->buf;
	size_t len = result->length;
	ccn_content_get_value(ptr, len, &pco, &ptr, &len);

	ccn_charbuf *key = ccn_charbuf_create();
	ccn_charbuf_reserve(key, len);
	memcpy(key->buf, ptr, len);
	key->length = len;
	
	std::string keyNameStr = charbuf_to_string(name);
	CcnxKeyObjectPtr keyObjectPtr(new CcnxKeyObject(keyNameStr, key, timestamp, freshness));
	ccn_destroy(&h);
	ccn_charbuf_destroy(&result);
	ccn_charbuf_destroy(&key);
	ccn_charbuf_destroy(&name);
	return keyObjectPtr;
}
