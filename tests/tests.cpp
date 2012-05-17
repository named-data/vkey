#define BOOST_TEST_MODULE testvkey
#include <boost/test/unit_test.hpp>
#include <boost/test/output_test_stream.hpp>
using boost::test_tools::output_test_stream;

#include <iostream>
#include "../src/vkey.hpp"
#include <cstdio>

using namespace std;
using namespace VKey;
using namespace boost;

BOOST_AUTO_TEST_CASE(KeyObjectTest)
{
	unsigned char *keydata = NULL;
	size_t kd_size, len;
	FILE *fp = fopen("./.ccnx/.keystore", "r");
	BOOST_CHECK(fp != NULL);
	X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
    kd_size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &keydata);
	BOOST_CHECK(kd_size > 0);

	ccn_charbuf *key = ccn_charbuf_create();
	ccn_charbuf_reserve(key, kd_size);
	memcpy(key->buf, keydata, kd_size);
	key->length = kd_size;
	
	time_t now = time(NULL);
	int freshness = 1;
	now -= freshness * 60 * 60 * 24;
	now += 1;

	CcnxKeyObjectPtr ptr(new CcnxKeyObject("/ndn/test/key", key, now, freshness));	
	
	BOOST_CHECK_EQUAL(ptr->getKeyName(), "/ndn/test/key");
	BOOST_CHECK_EQUAL(ptr->getTimestamp(), now);
	BOOST_CHECK_EQUAL(ptr->getFreshness(), freshness);
	BOOST_CHECK(ptr->getCcnPKey() != NULL);
	BOOST_CHECK(!ptr->expired())

	sleep(1);

	BOOST_CHECK(ptr->expired())
}

