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

using namespace VKey;

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
	std::string name = ccn_charbuf_as_string(keyName);
	
	ccn_pkey *pubkey = NULL;

	// check keymap first
	CcnxKeyObjectPtr keyObjectPtr = lookupKeyInKeyMap(name);
	if (keyObjectPtr != CcnxKeyObject::Null) {
		if (keyObjectPtr->expired()) {
			deleteKeyFromKeyMap(name);
			keyObjectPtr = CcnxKeyObject::Null;
		}
	} else {
		// next check the keyDB
		keyObjectPtr = lookupKeyInKeyDB(name);
		if (keyObjectPtr != CcnxKeyObject::Null) {
			// no need to check whether expired or not
			// we did the cleaning before lookup in DB

			// store it to the cache so we don't need to check DB next time
			addKeyToKeyMap(keyObjectPtr);
		} else {
			// finally, try to fetch from the network
			keyObjectPtr = lookupKeyInNetwork(keyName);
			if (keyObjectPtr != CcnxKeyObject::Null) {
				// the key (not only the local copy) is expired
				// there is no way to verify the signature
				if (keyObjectPtr->expired()) {
					ccn_charbuf_destroy(&keyName);
					return false;
				}
				// store it to DB and cache
				addKeyToKeyMap(keyObjectPtr);
				addKeyToKeyDB(keyObjectPtr);
			}
		}
	}
	
	if (keyObjectPtr != CcnxKeyObject::Null) {
		ccn_charbuf *key = keyObjectPtr->getKey();
		pubkey = ccn_d2i_pubkey(key->buf, key->length);
		bool verified = false;
		if (pubkey != NULL) {
			verified = (ccn_verify_signature((unsigned char *) ccnb, pco->offset[CCN_PCO_E], pco, pubkey) == 0);
		}
		ccn_charbuf_destroy(&key);
		ccn_charbuf_destroy(&keyName);
		return verified;
	}
	
	ccn_charbuf_destroy(&keyName);
	return false;

}

SigVerifier::SigVerifier(): m_dbManager(new SqliteKeyDBManager) {
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
CcnxKeyObject::Null;

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

SqliteKeyDBManager::SqliteKeyDBManager() {
	char *dbLoc = NULL;
	dbLoc = std::getenv("DB_FILE");
	m_dbFile = (dbLoc != NULL) ? dbLoc : std::getenv("HOME");
	m_dbFile += "/.ccnx/.vkey.db";
	
	m_tableReady = false;
	sqlite3 *db;
	if (sqlite3_open(m_dbFile.c_str(), &db) == SQLITE_OK) {
		int rc = sqlite3_exec(db, "create table if not exists trusted_keys(name TEXT, key BLOB, timestamp INTEGER, valid_to INTEGER);", NULL, NULL, NULL);
		if (rc == SQLITE_OK) {
			m_tableReady = true;
		}
		sqlite3_close(db);
	}
}

bool 
SqliteKeyDBManager::insert(const CcnxKeyObjectPtr keyObjectPtr) {
	if (!checkAndOpenDB())
		return false;

	sqlite3_stmt *stmt;	
	const char *zSql = "INSERT INTO trusted_keys VALUES(?,?,?,?);";
	sqlite3_prepare_v2(db, zSql, -1, &stmt, NULL);
	std::string name = keyObjectPtr->getKeyName();
	ccn_charbuf *key = keyObjectPtr->getKey();
	sqlite3_bind_text(stmt, 1, name.c_str(), name.length(), SQLITE_STATIC);
	sqlite3_bind_blob(stmt, 2, key->buf, key->length, SQLITE_STATIC);
	int timestamp = keyObjectPtr->getTimestamp();
	int valid_to = timestamp + keyObjectPtr->getTimestamp() * 60 * 60 * 24;
	sqlite3_bind_int(stmt, 3, timestamp);
	sqlite3_bind_int(stmt, 4, valid_to);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	ccn_charbuf_destroy(&key);
	return true;
}

const CcnxKeyObjectPtr 
SqliteKeyDBManager::query(const std::string keyName) {
	if (!checkAndOpenDB())
		return CcnxKeyObject::Null;

	sqlite3_stmt *stmt;	
	const char *zSql = "SELECT * FROM trusted_keys WHERE name == ?;";
	sqlite3_prepare_v2(db, zSql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, keyName.c_str(), keyName.length(), SQLITE_STATIC);
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

		return ptr;
	}

	return CcnxKeyObject::Null;
}

bool 
SqliteKeyDBManager::update() {
	if (!checkAndOpenDB())
		return false;

	time_t now = time(NULL);

	sqlite3_stmt *stmt;
	const char *zSql = "DELETE FROM trusted_keys WHERE valid_to < ?;";
	sqlite3_prepare_v2(db, zSql, -1, &stmt, NULL);
	sqlite3_bind_int(stmt, 1, (int) now);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	return true;
}


bool 
SqliteKeyDBManager::checkAndOpenDB() {
	if (!m_tableReady)
		return false;
	
	sqlite3 *db;
	if (sqlite3_open(m_dbFile.c_str(), &db) != SQLITE_OK)
		return false;
	
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
		return CcnxKeyObject::Null;
	}

	// verify fetched key object
	SigVerifier *verifier = SigVerifier::getInstance();
	// the signature of the key object can not be verified
	if(!verifier->verify(result->buf, &pco)) {
		return CcnxKeyObject::Null;
	}
	
	time_t timestamp = 0;
	if (get_timestamp_in_seconds(result, pco, &timestamp) < 0) {
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
	
	std::string keyNameStr = ccn_charbuf_as_string(name);
	CcnxKeyObjectPtr keyObjectPtr(new CcnxKeyObject(keyNameStr, key, timestamp, freshness));
	ccn_destroy(&h);
	ccn_charbuf_destroy(&result);
	ccn_charbuf_destroy(&key);
	ccn_charbuf_destroy(&name);
	return keyObjectPtr;
}
