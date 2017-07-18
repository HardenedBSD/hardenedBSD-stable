/*
 * Copyright (c) 2015 Joel Sing <jsing@openbsd.org>
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

#include <openssl/dtls1.h>
#include <openssl/ssl3.h>

#include <err.h>
#include <stdio.h>
#include <string.h>

#define DTLS_HM_OFFSET (DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH)
#define DTLS_RANDOM_OFFSET (DTLS_HM_OFFSET + 2)
#define DTLS_CIPHER_OFFSET (DTLS_HM_OFFSET + 38)

#define SSL3_HM_OFFSET (SSL3_RT_HEADER_LENGTH + SSL3_HM_HEADER_LENGTH)
#define SSL3_RANDOM_OFFSET (SSL3_HM_OFFSET + 2)
#define SSL3_CIPHER_OFFSET (SSL3_HM_OFFSET + 37)

static unsigned char cipher_list_dtls1[] = {
	0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38,
	0xff, 0x85, 0x00, 0x88, 0x00, 0x87, 0x00, 0x81,
	0x00, 0x35, 0x00, 0x84, 0xc0, 0x13, 0xc0, 0x09,
	0x00, 0x33, 0x00, 0x32, 0x00, 0x45, 0x00, 0x44,
	0x00, 0x2f, 0x00, 0x41, 0xc0, 0x12, 0xc0, 0x08,
	0x00, 0x16, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x15,
	0x00, 0x12, 0x00, 0x09, 0x00, 0xff,
};

static unsigned char client_hello_dtls1[] = {
	0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00,
	0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x64, 0xfe, 0xff, 0xc3, 0xd6, 0x19, 0xf8, 0x5d,
	0x6a, 0xe3, 0x6d, 0x16, 0x4a, 0xf7, 0x8f, 0x8e,
	0x4a, 0x12, 0x87, 0xcf, 0x07, 0x99, 0xa7, 0x92,
	0x40, 0xbd, 0x06, 0x9f, 0xe9, 0xd2, 0x68, 0x84,
	0xff, 0x6f, 0xe8, 0x00, 0x00, 0x00, 0x36, 0xc0,
	0x14, 0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38, 0xff,
	0x85, 0x00, 0x88, 0x00, 0x87, 0x00, 0x81, 0x00,
	0x35, 0x00, 0x84, 0xc0, 0x13, 0xc0, 0x09, 0x00,
	0x33, 0x00, 0x32, 0x00, 0x45, 0x00, 0x44, 0x00,
	0x2f, 0x00, 0x41, 0xc0, 0x12, 0xc0, 0x08, 0x00,
	0x16, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x15, 0x00,
	0x12, 0x00, 0x09, 0x00, 0xff, 0x01, 0x00, 0x00,
	0x04, 0x00, 0x23, 0x00, 0x00,
};

static unsigned char cipher_list_tls10[] = {
	0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38,
	0xff, 0x85, 0x00, 0x88, 0x00, 0x87, 0x00, 0x81,
	0x00, 0x35, 0x00, 0x84, 0xc0, 0x13, 0xc0, 0x09,
	0x00, 0x33, 0x00, 0x32, 0x00, 0x45, 0x00, 0x44,
	0x00, 0x2f, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07,
	0x00, 0x05, 0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08,
	0x00, 0x16, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x15,
	0x00, 0x12, 0x00, 0x09, 0x00, 0xff,
};

static unsigned char client_hello_tls10[] = {
	0x16, 0x03, 0x01, 0x00, 0x81, 0x01, 0x00, 0x00,
	0x7d, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xc0, 0x14,
	0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38, 0xff, 0x85,
	0x00, 0x88, 0x00, 0x87, 0x00, 0x81, 0x00, 0x35,
	0x00, 0x84, 0xc0, 0x13, 0xc0, 0x09, 0x00, 0x33,
	0x00, 0x32, 0x00, 0x45, 0x00, 0x44, 0x00, 0x2f,
	0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05,
	0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16,
	0x00, 0x13, 0x00, 0x0a, 0x00, 0x15, 0x00, 0x12,
	0x00, 0x09, 0x00, 0xff, 0x01, 0x00, 0x00, 0x16,
	0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a,
	0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17,
	0x00, 0x18, 0x00, 0x23, 0x00, 0x00,
};

static unsigned char cipher_list_tls11[] = {
	0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38,
	0xff, 0x85, 0x00, 0x88, 0x00, 0x87, 0x00, 0x81,
	0x00, 0x35, 0x00, 0x84, 0xc0, 0x13, 0xc0, 0x09,
	0x00, 0x33, 0x00, 0x32, 0x00, 0x45, 0x00, 0x44,
	0x00, 0x2f, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07,
	0x00, 0x05, 0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08,
	0x00, 0x16, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x15,
	0x00, 0x12, 0x00, 0x09, 0x00, 0xff,
};

static unsigned char client_hello_tls11[] = {
	0x16, 0x03, 0x01, 0x00, 0x81, 0x01, 0x00, 0x00,
	0x7d, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xc0, 0x14,
	0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38, 0xff, 0x85,
	0x00, 0x88, 0x00, 0x87, 0x00, 0x81, 0x00, 0x35,
	0x00, 0x84, 0xc0, 0x13, 0xc0, 0x09, 0x00, 0x33,
	0x00, 0x32, 0x00, 0x45, 0x00, 0x44, 0x00, 0x2f,
	0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05,
	0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16,
	0x00, 0x13, 0x00, 0x0a, 0x00, 0x15, 0x00, 0x12,
	0x00, 0x09, 0x00, 0xff, 0x01, 0x00, 0x00, 0x16,
	0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a,
	0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17,
	0x00, 0x18, 0x00, 0x23, 0x00, 0x00,
};

static unsigned char cipher_list_tls12_aes[] = {
	0xc0, 0x30, 0xc0, 0x2c, 0xc0, 0x28, 0xc0, 0x24,
	0xc0, 0x14, 0xc0, 0x0a, 0x00, 0xa3, 0x00, 0x9f,
	0x00, 0x6b, 0x00, 0x6a, 0x00, 0x39, 0x00, 0x38,
	0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xcc, 0x14,
	0xcc, 0x13, 0xcc, 0x15, 0xff, 0x85, 0x00, 0xc4,
	0x00, 0xc3, 0x00, 0x88, 0x00, 0x87, 0x00, 0x81,
	0x00, 0x9d, 0x00, 0x3d, 0x00, 0x35, 0x00, 0xc0,
	0x00, 0x84, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27,
	0xc0, 0x23, 0xc0, 0x13, 0xc0, 0x09, 0x00, 0xa2,
	0x00, 0x9e, 0x00, 0x67, 0x00, 0x40, 0x00, 0x33,
	0x00, 0x32, 0x00, 0xbe, 0x00, 0xbd, 0x00, 0x45,
	0x00, 0x44, 0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f,
	0x00, 0xba, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07,
	0x00, 0x05, 0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08,
	0x00, 0x16, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x15,
	0x00, 0x12, 0x00, 0x09, 0x00, 0xff,
};

static unsigned char cipher_list_tls12_chacha[] = {
	0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xcc, 0x14,
	0xcc, 0x13, 0xcc, 0x15, 0xc0, 0x30, 0xc0, 0x2c,
	0xc0, 0x28, 0xc0, 0x24, 0xc0, 0x14, 0xc0, 0x0a,
	0x00, 0xa3, 0x00, 0x9f, 0x00, 0x6b, 0x00, 0x6a,
	0x00, 0x39, 0x00, 0x38, 0xff, 0x85, 0x00, 0xc4,
	0x00, 0xc3, 0x00, 0x88, 0x00, 0x87, 0x00, 0x81,
	0x00, 0x9d, 0x00, 0x3d, 0x00, 0x35, 0x00, 0xc0,
	0x00, 0x84, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27,
	0xc0, 0x23, 0xc0, 0x13, 0xc0, 0x09, 0x00, 0xa2,
	0x00, 0x9e, 0x00, 0x67, 0x00, 0x40, 0x00, 0x33,
	0x00, 0x32, 0x00, 0xbe, 0x00, 0xbd, 0x00, 0x45,
	0x00, 0x44, 0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f,
	0x00, 0xba, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07,
	0x00, 0x05, 0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08,
	0x00, 0x16, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x15,
	0x00, 0x12, 0x00, 0x09, 0x00, 0xff,
};

static unsigned char client_hello_tls12[] = {
	0x16, 0x03, 0x01, 0x00, 0xeb, 0x01, 0x00, 0x00,
	0xe7, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0xcc, 0xa9,
	0xcc, 0xa8, 0xcc, 0xaa, 0xcc, 0x14, 0xcc, 0x13,
	0xcc, 0x15, 0xc0, 0x30, 0xc0, 0x2c, 0xc0, 0x28,
	0xc0, 0x24, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0xa3,
	0x00, 0x9f, 0x00, 0x6b, 0x00, 0x6a, 0x00, 0x39,
	0x00, 0x38, 0xff, 0x85, 0x00, 0xc4, 0x00, 0xc3,
	0x00, 0x88, 0x00, 0x87, 0x00, 0x81, 0x00, 0x9d,
	0x00, 0x3d, 0x00, 0x35, 0x00, 0xc0, 0x00, 0x84,
	0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27, 0xc0, 0x23,
	0xc0, 0x13, 0xc0, 0x09, 0x00, 0xa2, 0x00, 0x9e,
	0x00, 0x67, 0x00, 0x40, 0x00, 0x33, 0x00, 0x32,
	0x00, 0xbe, 0x00, 0xbd, 0x00, 0x45, 0x00, 0x44,
	0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0xba,
	0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05,
	0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16,
	0x00, 0x13, 0x00, 0x0a, 0x00, 0x15, 0x00, 0x12,
	0x00, 0x09, 0x00, 0xff, 0x01, 0x00, 0x00, 0x40,
	0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a,
	0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17,
	0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d,
	0x00, 0x26, 0x00, 0x24, 0x06, 0x01, 0x06, 0x02,
	0x06, 0x03, 0xef, 0xef, 0x05, 0x01, 0x05, 0x02,
	0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03,
	0xee, 0xee, 0xed, 0xed, 0x03, 0x01, 0x03, 0x02,
	0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
};

struct client_hello_test {
	const unsigned char *desc;
	const int protocol;
	const size_t random_start;
	const SSL_METHOD *(*ssl_method)(void);
	const long ssl_options;
};

static struct client_hello_test client_hello_tests[] = {
	{
		.desc = "DTLSv1 client",
		.protocol = DTLS1_VERSION,
		.random_start = DTLS_RANDOM_OFFSET,
		.ssl_method = DTLSv1_client_method,
	},
	{
		.desc = "TLSv1 client",
		.protocol = TLS1_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = TLSv1_client_method,
	},
	{
		.desc = "TLSv1_1 client",
		.protocol = TLS1_1_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = TLSv1_1_client_method,
	},
	{
		.desc = "TLSv1_2 client",
		.protocol = TLS1_2_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = TLSv1_2_client_method,
	},
	{
		.desc = "SSLv23 default",
		.protocol = TLS1_2_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = SSLv23_client_method,
		.ssl_options = 0,
	},
	{
		.desc = "SSLv23 (no TLSv1.2)",
		.protocol = TLS1_1_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = SSLv23_client_method,
		.ssl_options = SSL_OP_NO_TLSv1_2,
	},
	{
		.desc = "SSLv23 (no TLSv1.1)",
		.protocol = TLS1_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = SSLv23_client_method,
		.ssl_options = SSL_OP_NO_TLSv1_1,
	},
	{
		.desc = "TLS default",
		.protocol = TLS1_2_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = TLS_client_method,
		.ssl_options = 0,
	},
	{
		.desc = "TLS (no TLSv1.2)",
		.protocol = TLS1_1_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = TLS_client_method,
		.ssl_options = SSL_OP_NO_TLSv1_2,
	},
	{
		.desc = "TLS (no TLSv1.1)",
		.protocol = TLS1_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = TLS_client_method,
		.ssl_options = SSL_OP_NO_TLSv1_1,
	},
	{
		.desc = "TLS (no TLSv1.0, no TLSv1.1)",
		.protocol = TLS1_2_VERSION,
		.random_start = SSL3_RANDOM_OFFSET,
		.ssl_method = TLS_client_method,
		.ssl_options = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1,
	},
};

#define N_CLIENT_HELLO_TESTS \
    (sizeof(client_hello_tests) / sizeof(*client_hello_tests))

static void
hexdump(const unsigned char *buf, size_t len)
{
	size_t i;

	for (i = 1; i <= len; i++)
		fprintf(stderr, " 0x%02hhx,%s", buf[i - 1], i % 8 ? "" : "\n");

	fprintf(stderr, "\n");
}

static inline int
ssl_aes_is_accelerated(void)
{
#if defined(__i386__) || defined(__x86_64__)
	return ((OPENSSL_cpu_caps() & (1ULL << 57)) != 0);
#else
	return (0);
#endif
}

static int
make_client_hello(int protocol, char **out, size_t *outlen)
{
	size_t client_hello_len, cipher_list_len, cipher_list_offset;
	const char *client_hello, *cipher_list;
	char *p;
	
	*out = NULL;
	*outlen = 0;

	switch (protocol) {
	case DTLS1_VERSION:
		client_hello = client_hello_dtls1;
		client_hello_len = sizeof(client_hello_dtls1);
		cipher_list = cipher_list_dtls1;
		cipher_list_len = sizeof(cipher_list_dtls1);
		cipher_list_offset = DTLS_CIPHER_OFFSET;
		break;
	
	case TLS1_VERSION:
		client_hello = client_hello_tls10;
		client_hello_len = sizeof(client_hello_tls10);
		cipher_list = cipher_list_tls10;
		cipher_list_len = sizeof(cipher_list_tls10);
		cipher_list_offset = SSL3_CIPHER_OFFSET;
		break;

	case TLS1_1_VERSION:
		client_hello = client_hello_tls11;
		client_hello_len = sizeof(client_hello_tls11);
		cipher_list = cipher_list_tls11;
		cipher_list_len = sizeof(cipher_list_tls11);
		cipher_list_offset = SSL3_CIPHER_OFFSET;
		break;

	case TLS1_2_VERSION:
		client_hello = client_hello_tls12;
		client_hello_len = sizeof(client_hello_tls12);
		if (ssl_aes_is_accelerated() == 1)
			cipher_list = cipher_list_tls12_aes;
		else
			cipher_list = cipher_list_tls12_chacha;
		cipher_list_len = sizeof(cipher_list_tls12_chacha);
		cipher_list_offset = SSL3_CIPHER_OFFSET;
		break;
	
	default:
		return (-1);
	}

	if ((p = malloc(client_hello_len)) == NULL)
		return (-1);

	memcpy(p, client_hello, client_hello_len);
	memcpy(p + cipher_list_offset, cipher_list, cipher_list_len);

	*out = p;
	*outlen = client_hello_len;

	return (0);
}

static int
client_hello_test(int testno, struct client_hello_test *cht)
{
	BIO *rbio = NULL, *wbio = NULL;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	char *client_hello = NULL;
	size_t client_hello_len;
	char *wbuf, rbuf[1];
	int ret = 1;
	size_t i;
	long len;

	fprintf(stderr, "Test %i - %s\n", testno, cht->desc);

	/* Providing a small buf causes *_get_server_hello() to return. */
	if ((rbio = BIO_new_mem_buf(rbuf, sizeof(rbuf))) == NULL) {
		fprintf(stderr, "Failed to setup rbio\n");
		goto failure;
	}
	if ((wbio = BIO_new(BIO_s_mem())) == NULL) {
		fprintf(stderr, "Failed to setup wbio\n");
		goto failure;
	}

	if ((ssl_ctx = SSL_CTX_new(cht->ssl_method())) == NULL) {
		fprintf(stderr, "SSL_CTX_new() returned NULL\n");
		goto failure;
	}

	SSL_CTX_set_options(ssl_ctx, cht->ssl_options);

	if ((ssl = SSL_new(ssl_ctx)) == NULL) {
		fprintf(stderr, "SSL_new() returned NULL\n");
		goto failure;
	}

	rbio->references = 2;
	wbio->references = 2;

	SSL_set_bio(ssl, rbio, wbio);
	
	if (SSL_connect(ssl) != 0) {
		fprintf(stderr, "SSL_connect() returned non-zero\n");
		goto failure;
	}

	len = BIO_get_mem_data(wbio, &wbuf);

	if (make_client_hello(cht->protocol, &client_hello,
	    &client_hello_len) != 0)
		goto failure;

	if ((size_t)len != client_hello_len) {
		fprintf(stderr, "FAIL: test returned ClientHello length %li, "
		    "want %zu\n", len, client_hello_len);
		fprintf(stderr, "received:\n");
		hexdump(wbuf, len);
		goto failure;
	}

	/* We expect the client random to differ. */
	i = cht->random_start + SSL3_RANDOM_SIZE;
	if (memcmp(client_hello, wbuf, cht->random_start) != 0 ||
	    memcmp(&client_hello[cht->random_start],
		&wbuf[cht->random_start], SSL3_RANDOM_SIZE) == 0 ||
	    memcmp(&client_hello[i], &wbuf[i], len - i) != 0) {
		fprintf(stderr, "FAIL: ClientHello differs:\n");
		fprintf(stderr, "received:\n");
		hexdump(wbuf, len);
		fprintf(stderr, "test data:\n");
		hexdump(client_hello, client_hello_len);
		fprintf(stderr, "\n");
		goto failure;
	}
	
	ret = 0;

failure:
	SSL_CTX_free(ssl_ctx);
	SSL_free(ssl);

	rbio->references = 1;
	wbio->references = 1;

	BIO_free(rbio);
	BIO_free(wbio);

	free(client_hello);

	return (ret);
}

int
main(int argc, char **argv)
{
	int failed = 0;
	size_t i;

	SSL_library_init();

	for (i = 0; i < N_CLIENT_HELLO_TESTS; i++)
		failed |= client_hello_test(i, &client_hello_tests[i]);

	return (failed);
}
