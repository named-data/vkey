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

#ifndef VKEY_HPP
#define VKEY_HPP
#include <map>
#include <utility>
#include <tr1/memory>
#include <string>
#include <sqlite3.h>
#include <ctime>
#include <cstdlib>
#include "ccnx_util.hpp"

namespace VKey {

class KeyDBManager;
class SqliteManager;
class CcnxKeyObject;
typedef std::tr1::shared_ptr<CcnxKeyObject> CcnxKeyObjectPtr;
typedef std::map<std::string, CcnxKeyObjectPtr> KeyMap;	

// Singleton pattern
// there is only one instance of this class
// for each application
class SigVerifier {
public:
	static SigVerifier *getInstance();	
	bool verify(ccn_upcall_info *);
	bool verify(const unsigned char *ccnb, ccn_parsed_ContentObject *pco);

private:
	SigVerifier();
	// no destructor for this singleton pattern yet..
	// shall we create a SigVeriferDestroyer class
	// for this purpose?
	void addKeyToKeyMap(const CcnxKeyObjectPtr keyObjectPtr);
	void addKeyToKeyDB(const CcnxKeyObjectPtr keyObjectPtr);
	void deleteKeyFromKeyMap(const std::string name);
	CcnxKeyObjectPtr lookupKeyInKeyMap(const std::string name);
	CcnxKeyObjectPtr lookupKeyInKeyDB(const std::string name);
	CcnxKeyObjectPtr lookupKeyInNetwork(const ccn_charbuf *keyName);
	CcnxKeyObjectPtr lookupKey(const std::string name);
	bool isStrict(std::string name, std::string keyName);

private:
	static SigVerifier *sigVerifier;
	KeyMap m_keyMap;
	std::auto_ptr<KeyDBManager> m_dbManager;
	CcnxKeyObjectPtr m_rootKeyObjectPtr;
};

class CcnxKeyObject{
public:
	static CcnxKeyObjectPtr Null;
	CcnxKeyObject(const std::string keyName, const ccn_charbuf *key, time_t timestamp, int freshness);
	~CcnxKeyObject();

	std::string getKeyName();
	// client is responsible to free the memory
	// get key in ccn_charbuf format (network format)
	ccn_charbuf *getKey();
	time_t getTimestamp() {return m_timestamp;}
	int getFreshness() {return m_freshness;}
	// whether the associated key is expired
	bool expired();
	// ccn_pkey format for ccnx code to use
	// client is responsible to free the memory
	// DANGER: here we will return the pointer m_ccnPKey to clients
	// we trust clients won't be modifying m_ccnPKey
	// we decided to do so because returning a (bit-wise) copy of m_ccnPKey
	// and use ccn_pubkey_free to free the copy seems to have
	// a side effiect of chaing the original copy of m_ccnPKey
	// somthing fishy is going on in ccn_pubkey_free
	// or bit-wise copy of EVP_PKEY is wrong
	// somebody suggested using the following code to dup EVP_PKEY
	// we can try that if needed
	/***********************
	I ended up with the following code, which seems to works fine:

	EVP_PKEY* pDupKey = EVP_PKEY_new();
	RSA* pRSA = EVP_PKEY_get1_RSA(pKey);
	RSA* pRSADupKey;
	if( eKeyType == eKEY_PUBLIC ) // Determine the type of the "source" EVP_PKEY
		  pRSADupKey = RSAPublicKey_dup(pRSA);
		  else
			    pRSADupKey = RSAPrivateKey_dup(pRSA);
				RSA_free(pRSA);
				EVP_PKEY_set1_RSA(pDupKey, pRSADupKey);
				RSA_free(pRSADupKey);
				return(pDupKey);
	************************/
			
	ccn_pkey *getCcnPKey();

private:
	std::string m_keyName;
	// m_key->buf: key
	// m_key->length: key size
	ccn_charbuf *m_key;
	// timestamp in seconds
	time_t m_timestamp;
	// unit for freshness is day
	int m_freshness;
	// the ccn_pkey structure for ccn to use
	ccn_pkey *m_ccnPKey;
};

class KeyDBManager {
public:
	virtual ~KeyDBManager(){};
	virtual bool insert(const CcnxKeyObjectPtr keyObjectPtr) = 0;
	virtual const CcnxKeyObjectPtr query(const std::string keyName) = 0;
	virtual bool update() = 0;
};

class SqliteKeyDBManager: public KeyDBManager{
public:
	SqliteKeyDBManager();
	virtual ~SqliteKeyDBManager(){};
	virtual bool insert(const CcnxKeyObjectPtr keyObjectPtr);
	virtual const CcnxKeyObjectPtr query(const std::string keyName); 
	// get rid of keys that are already expired
	virtual bool update();

private:
	bool checkAndOpenDB();

private:
	std::string m_dbFile;
	std::string m_tableName;
	bool m_tableReady;
	sqlite3 *m_db;
};

class CcnxOneTimeKeyFetcher {
public:
	static const CcnxKeyObjectPtr fetch(const ccn_charbuf *keyName);
};

}

#endif // VKEY_HPP
