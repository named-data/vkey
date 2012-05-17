#ifndef CCNX_UTIL_H
#define CCNX_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/signing.h>
#ifdef __cplusplus
}
#endif
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

ccn_charbuf *
ccn_charbuf_dup(const ccn_charbuf *target);

// return 0 for success; otherwise failure
int
get_timestamp_in_seconds(const ccn_charbuf *target, const ccn_parsed_ContentObject &pco, time_t *timestamp);

int
get_freshness_in_days(const ccn_charbuf *target, const ccn_parsed_ContentObject &pco);

int
contain_key_name(const unsigned char *ccnb, ccn_parsed_ContentObject *pco);

ccn_charbuf *
get_key_name(const unsigned char *ccnb, ccn_parsed_ContentObject *pco);
#endif // CCNX_UTIL_H
