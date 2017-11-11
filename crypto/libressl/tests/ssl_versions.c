/* $OpenBSD: ssl_versions.c,v 1.4 2017/05/06 20:39:03 jsing Exp $ */
/*
 * Copyright (c) 2016, 2017 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/ssl.h>

#include "ssl_locl.h"

struct version_range_test {
	const long options;
	const uint16_t minver;
	const uint16_t maxver;
	const uint16_t want_minver;
	const uint16_t want_maxver;
};

static struct version_range_test version_range_tests[] = {
	{
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.options = SSL_OP_NO_TLSv1,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.options = SSL_OP_NO_TLSv1_2,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.options = SSL_OP_NO_TLSv1_1,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_VERSION,
	},
	{
		.options = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_2_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.options = SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_VERSION,
	},
	{
		.options = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_2,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_1_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.options = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = 0,
		.want_maxver = 0,
	},
	{
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.options = 0,
		.minver = TLS1_1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.options = 0,
		.minver = TLS1_2_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_2_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_1_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_VERSION,
	},
};

#define N_VERSION_RANGE_TESTS \
    (sizeof(version_range_tests) / sizeof(*version_range_tests))

static int
test_ssl_enabled_version_range(void)
{
	struct version_range_test *vrt;
	uint16_t minver, maxver;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	int failed = 1;
	size_t i;

	if ((ssl_ctx = SSL_CTX_new(TLS_method())) == NULL) { 
		fprintf(stderr, "SSL_CTX_new() returned NULL\n");
		goto failure;
	}
	if ((ssl = SSL_new(ssl_ctx)) == NULL) {
		fprintf(stderr, "SSL_new() returned NULL\n");
		goto failure;
	}

	failed = 0;

	for (i = 0; i < N_VERSION_RANGE_TESTS; i++) {
		vrt = &version_range_tests[i];

		SSL_clear_options(ssl, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
		    SSL_OP_NO_TLSv1_2);
		SSL_set_options(ssl, vrt->options);

		minver = maxver = 0xffff;
		ssl->internal->min_version = vrt->minver;
		ssl->internal->max_version = vrt->maxver;

		if (ssl_enabled_version_range(ssl, &minver, &maxver) != 1) {
			if (vrt->want_minver != 0 || vrt->want_maxver != 0) {
				fprintf(stderr, "FAIL: test %zu - failed but "
				    "wanted non-zero versions\n", i);
				failed++;
			}
			continue;
		}
		if (minver != vrt->want_minver) {
			fprintf(stderr, "FAIL: test %zu - got minver %x, "
			    "want %x\n", i, minver, vrt->want_minver);
			failed++;
		}
		if (maxver != vrt->want_maxver) {
			fprintf(stderr, "FAIL: test %zu - got maxver %x, "
			    "want %x\n", i, maxver, vrt->want_maxver);
			failed++;
		}
	}

 failure:
	SSL_CTX_free(ssl_ctx);
	SSL_free(ssl);

	return (failed);
}

struct shared_version_test {
	const SSL_METHOD *(*ssl_method)(void);
	const long options;
	const uint16_t minver;
	const uint16_t maxver;
	const uint16_t peerver;
	const uint16_t want_maxver;
};

static struct shared_version_test shared_version_tests[] = {
	{
		.ssl_method = TLS_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = SSL2_VERSION,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLS_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = SSL3_VERSION,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLS_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_VERSION,
		.want_maxver = TLS1_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_1_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_2_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = 0x7f12,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.options = SSL_OP_NO_TLSv1_2,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_2_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.options = SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_2_VERSION,
		.want_maxver = TLS1_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.options = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_2_VERSION,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLS_method,
		.options = SSL_OP_NO_TLSv1,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_1_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.options = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_1_VERSION,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLS_method,
		.options = SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_1_VERSION,
		.want_maxver = TLS1_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.options = SSL_OP_NO_TLSv1,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_VERSION,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLS_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_1_VERSION,
		.peerver = TLS1_2_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_VERSION,
		.peerver = TLS1_2_VERSION,
		.want_maxver = TLS1_VERSION,
	},
	{
		.ssl_method = TLSv1_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_VERSION,
		.want_maxver = TLS1_VERSION,
	},
	{
		.ssl_method = TLSv1_method,
		.options = 0,
		.minver = TLS1_1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_VERSION,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLSv1_1_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_1_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.ssl_method = DTLSv1_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = DTLS1_VERSION,
		.want_maxver = DTLS1_VERSION,
	},
	{
		.ssl_method = DTLSv1_method,
		.options = 0,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.peerver = TLS1_2_VERSION,
		.want_maxver = 0,
	},
};

#define N_SHARED_VERSION_TESTS \
    (sizeof(shared_version_tests) / sizeof(*shared_version_tests))

static int
test_ssl_max_shared_version(void)
{
	struct shared_version_test *svt;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	uint16_t maxver;
	int failed = 0;
	size_t i;

	failed = 0;

	for (i = 0; i < N_SHARED_VERSION_TESTS; i++) {
		svt = &shared_version_tests[i];

		if ((ssl_ctx = SSL_CTX_new(svt->ssl_method())) == NULL) { 
			fprintf(stderr, "SSL_CTX_new() returned NULL\n");
			return 1;
		}
		if ((ssl = SSL_new(ssl_ctx)) == NULL) {
			fprintf(stderr, "SSL_new() returned NULL\n");
			return 1;
		}

		SSL_clear_options(ssl, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
		    SSL_OP_NO_TLSv1_2);
		SSL_set_options(ssl, svt->options);

		maxver = 0;
		ssl->internal->min_version = svt->minver;
		ssl->internal->max_version = svt->maxver;

		if (ssl_max_shared_version(ssl, svt->peerver, &maxver) != 1) {
			if (svt->want_maxver != 0) {
				fprintf(stderr, "FAIL: test %zu - failed but "
				    "wanted non-zero shared version\n", i);
				failed++;
			}
			continue;
		}
		if (maxver != svt->want_maxver) {
			fprintf(stderr, "FAIL: test %zu - got shared "
			    "version %x, want %x\n", i, maxver,
			    svt->want_maxver);
			failed++;
		}

		SSL_CTX_free(ssl_ctx);
		SSL_free(ssl);
	}

	return (failed);
}

struct min_max_version_test {
	const SSL_METHOD *(*ssl_method)(void);
	const uint16_t minver;
	const uint16_t maxver;
	const uint16_t want_minver;
	const uint16_t want_maxver;
};

static struct min_max_version_test min_max_version_tests[] = {
	{
		.ssl_method = TLS_method,
		.minver = 0,
		.maxver = 0,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = TLS1_VERSION,
		.maxver = 0,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = 0,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = TLS1_1_VERSION,
		.maxver = 0,
		.want_minver = TLS1_1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = TLS1_2_VERSION,
		.maxver = 0,
		.want_minver = TLS1_2_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = 0x0300,
		.maxver = 0,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = 0x0305,
		.maxver = 0,
		.want_minver = 0,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLS_method,
		.minver = 0,
		.maxver = 0x0305,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_2_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = 0,
		.maxver = TLS1_1_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = 0,
		.maxver = TLS1_VERSION,
		.want_minver = TLS1_VERSION,
		.want_maxver = TLS1_VERSION,
	},
	{
		.ssl_method = TLS_method,
		.minver = 0,
		.maxver = 0x0300,
		.want_minver = 0,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLS_method,
		.minver = TLS1_2_VERSION,
		.maxver = TLS1_1_VERSION,
		.want_minver = TLS1_2_VERSION,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLSv1_1_method,
		.minver = 0,
		.maxver = 0,
		.want_minver = TLS1_1_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.ssl_method = TLSv1_1_method,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = TLS1_1_VERSION,
		.want_maxver = TLS1_1_VERSION,
	},
	{
		.ssl_method = TLSv1_1_method,
		.minver = TLS1_2_VERSION,
		.maxver = 0,
		.want_minver = 0,
		.want_maxver = 0,
	},
	{
		.ssl_method = TLSv1_1_method,
		.minver = 0,
		.maxver = TLS1_VERSION,
		.want_minver = 0,
		.want_maxver = 0,
	},
	{
		.ssl_method = DTLSv1_method,
		.minver = 0,
		.maxver = 0,
		.want_minver = DTLS1_VERSION,
		.want_maxver = DTLS1_VERSION,
	},
	{
		.ssl_method = DTLSv1_method,
		.minver = DTLS1_VERSION,
		.maxver = 0,
		.want_minver = DTLS1_VERSION,
		.want_maxver = DTLS1_VERSION,
	},
	{
		.ssl_method = DTLSv1_method,
		.minver = 0,
		.maxver = DTLS1_VERSION,
		.want_minver = DTLS1_VERSION,
		.want_maxver = DTLS1_VERSION,
	},
	{
		.ssl_method = DTLSv1_method,
		.minver = TLS1_VERSION,
		.maxver = TLS1_2_VERSION,
		.want_minver = 0,
		.want_maxver = 0,
	},
};

#define N_MIN_MAX_VERSION_TESTS \
    (sizeof(min_max_version_tests) / sizeof(*min_max_version_tests))

static int
test_ssl_min_max_version(void)
{
	struct min_max_version_test *mmvt;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	int failed = 0;
	size_t i;

	failed = 0;

	for (i = 0; i < N_SHARED_VERSION_TESTS; i++) {
		mmvt = &min_max_version_tests[i];

		if ((ssl_ctx = SSL_CTX_new(mmvt->ssl_method())) == NULL) { 
			fprintf(stderr, "SSL_CTX_new() returned NULL\n");
			return 1;
		}

		if (SSL_CTX_set_min_proto_version(ssl_ctx, mmvt->minver) != 1) {
			if (mmvt->want_minver != 0) {
				fprintf(stderr, "FAIL: test %zu - failed to set "
				    "SSL_CTX min version\n", i);
				failed++;
			}
			goto next;
		}
		if (SSL_CTX_set_max_proto_version(ssl_ctx, mmvt->maxver) != 1) {
			if (mmvt->want_maxver != 0) {
				fprintf(stderr, "FAIL: test %zu - failed to set "
				    "SSL_CTX min version\n", i);
				failed++;
			}
			goto next;
		}

		if (mmvt->want_minver == 0) {
			fprintf(stderr, "FAIL: test %zu - successfully set "
			    "SSL_CTX min version, should have failed\n", i);
			goto next;
		}
		if (mmvt->want_maxver == 0) {
			fprintf(stderr, "FAIL: test %zu - successfully set "
			    "SSL_CTX max version, should have failed\n", i);
			goto next;
		}

		if (ssl_ctx->internal->min_version != mmvt->want_minver) {
			fprintf(stderr, "FAIL: test %zu - got SSL_CTX min "
			    "version 0x%x, want 0x%x\n", i,
			    ssl_ctx->internal->min_version, mmvt->want_minver);
			goto next;
		}
		if (ssl_ctx->internal->max_version != mmvt->want_maxver) {
			fprintf(stderr, "FAIL: test %zu - got SSL_CTX max "
			    "version 0x%x, want 0x%x\n", i,
			    ssl_ctx->internal->max_version, mmvt->want_maxver);
			goto next;
		}

		if ((ssl = SSL_new(ssl_ctx)) == NULL) {
			fprintf(stderr, "SSL_new() returned NULL\n");
			return 1;
		}

		if (ssl->internal->min_version != mmvt->want_minver) {
			fprintf(stderr, "FAIL: test %zu - initial SSL min "
			    "version 0x%x, want 0x%x\n", i,
			    ssl_ctx->internal->min_version, mmvt->want_minver);
			goto next;
		}
		if (ssl->internal->max_version != mmvt->want_maxver) {
			fprintf(stderr, "FAIL: test %zu - initial SSL max "
			    "version 0x%x, want 0x%x\n", i,
			    ssl_ctx->internal->max_version, mmvt->want_maxver);
			goto next;
		}

		if (SSL_set_min_proto_version(ssl, mmvt->minver) != 1) {
			if (mmvt->want_minver != 0) {
				fprintf(stderr, "FAIL: test %zu - failed to set "
				    "SSL min version\n", i);
				failed++;
			}
			goto next;
		}
		if (SSL_set_max_proto_version(ssl, mmvt->maxver) != 1) {
			if (mmvt->want_maxver != 0) {
				fprintf(stderr, "FAIL: test %zu - failed to set "
				    "SSL min version\n", i);
				failed++;
			}
			goto next;
		}

		if (mmvt->want_minver == 0) {
			fprintf(stderr, "FAIL: test %zu - successfully set SSL "
			    "min version, should have failed\n", i);
			goto next;
		}
		if (mmvt->want_maxver == 0) {
			fprintf(stderr, "FAIL: test %zu - successfully set SSL "
			    "max version, should have failed\n", i);
			goto next;
		}

		if (ssl->internal->min_version != mmvt->want_minver) {
			fprintf(stderr, "FAIL: test %zu - got SSL min "
			    "version 0x%x, want 0x%x\n", i,
			    ssl_ctx->internal->min_version, mmvt->want_minver);
			goto next;
		}
		if (ssl->internal->max_version != mmvt->want_maxver) {
			fprintf(stderr, "FAIL: test %zu - got SSL max "
			    "version 0x%x, want 0x%x\n", i,
			    ssl->internal->max_version, mmvt->want_maxver);
			goto next;
		}

 next:
		SSL_CTX_free(ssl_ctx);
		SSL_free(ssl);

		ssl_ctx = NULL;
		ssl = NULL;
	}

	return (failed);
}

int
main(int argc, char **argv)
{
	int failed = 0;

	SSL_library_init();

	failed |= test_ssl_enabled_version_range();
	failed |= test_ssl_max_shared_version();
	failed |= test_ssl_min_max_version();

	if (failed == 0)
		printf("PASS %s\n", __FILE__);

        return (failed);
}
