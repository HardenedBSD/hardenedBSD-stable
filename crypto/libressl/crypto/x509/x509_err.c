/* $OpenBSD: x509_err.c,v 1.13 2017/01/29 17:49:23 beck Exp $ */
/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>

#include <openssl/opensslconf.h>

#include <openssl/err.h>
#include <openssl/x509.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(ERR_LIB_X509,func,0)
#define ERR_REASON(reason) ERR_PACK(ERR_LIB_X509,0,reason)

static ERR_STRING_DATA X509_str_functs[] = {
	{ERR_FUNC(0xfff), "CRYPTO_internal"},
	{0, NULL}
};

static ERR_STRING_DATA X509_str_reasons[] = {
	{ERR_REASON(X509_R_BAD_X509_FILETYPE)    , "bad x509 filetype"},
	{ERR_REASON(X509_R_BASE64_DECODE_ERROR)  , "base64 decode error"},
	{ERR_REASON(X509_R_CANT_CHECK_DH_KEY)    , "cant check dh key"},
	{ERR_REASON(X509_R_CERT_ALREADY_IN_HASH_TABLE), "cert already in hash table"},
	{ERR_REASON(X509_R_ERR_ASN1_LIB)         , "err asn1 lib"},
	{ERR_REASON(X509_R_INVALID_DIRECTORY)    , "invalid directory"},
	{ERR_REASON(X509_R_INVALID_FIELD_NAME)   , "invalid field name"},
	{ERR_REASON(X509_R_INVALID_TRUST)        , "invalid trust"},
	{ERR_REASON(X509_R_KEY_TYPE_MISMATCH)    , "key type mismatch"},
	{ERR_REASON(X509_R_KEY_VALUES_MISMATCH)  , "key values mismatch"},
	{ERR_REASON(X509_R_LOADING_CERT_DIR)     , "loading cert dir"},
	{ERR_REASON(X509_R_LOADING_DEFAULTS)     , "loading defaults"},
	{ERR_REASON(X509_R_METHOD_NOT_SUPPORTED) , "method not supported"},
	{ERR_REASON(X509_R_NO_CERT_SET_FOR_US_TO_VERIFY), "no cert set for us to verify"},
	{ERR_REASON(X509_R_PUBLIC_KEY_DECODE_ERROR), "public key decode error"},
	{ERR_REASON(X509_R_PUBLIC_KEY_ENCODE_ERROR), "public key encode error"},
	{ERR_REASON(X509_R_SHOULD_RETRY)         , "should retry"},
	{ERR_REASON(X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN), "unable to find parameters in chain"},
	{ERR_REASON(X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY), "unable to get certs public key"},
	{ERR_REASON(X509_R_UNKNOWN_KEY_TYPE)     , "unknown key type"},
	{ERR_REASON(X509_R_UNKNOWN_NID)          , "unknown nid"},
	{ERR_REASON(X509_R_UNKNOWN_PURPOSE_ID)   , "unknown purpose id"},
	{ERR_REASON(X509_R_UNKNOWN_TRUST_ID)     , "unknown trust id"},
	{ERR_REASON(X509_R_UNSUPPORTED_ALGORITHM), "unsupported algorithm"},
	{ERR_REASON(X509_R_WRONG_LOOKUP_TYPE)    , "wrong lookup type"},
	{ERR_REASON(X509_R_WRONG_TYPE)           , "wrong type"},
	{0, NULL}
};

#endif

void
ERR_load_X509_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(X509_str_functs[0].error) == NULL) {
		ERR_load_strings(0, X509_str_functs);
		ERR_load_strings(0, X509_str_reasons);
	}
#endif
}
