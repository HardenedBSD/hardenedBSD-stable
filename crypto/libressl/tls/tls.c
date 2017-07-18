/* $OpenBSD: tls.c,v 1.59 2017/01/26 12:56:37 jsing Exp $ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
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

#include <sys/socket.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <tls.h>
#include "tls_internal.h"

static struct tls_config *tls_config_default;

int
tls_init(void)
{
	static int tls_initialised = 0;

	if (tls_initialised)
		return (0);

	SSL_load_error_strings();
	SSL_library_init();

	if (BIO_sock_init() != 1)
		return (-1);

	if ((tls_config_default = tls_config_new()) == NULL)
		return (-1);

	tls_initialised = 1;

	return (0);
}

const char *
tls_error(struct tls *ctx)
{
	return ctx->error.msg;
}

void
tls_error_clear(struct tls_error *error)
{
	free(error->msg);
	error->msg = NULL;
	error->num = 0;
	error->tls = 0;
}

static int
tls_error_vset(struct tls_error *error, int errnum, const char *fmt, va_list ap)
{
	char *errmsg = NULL;
	int rv = -1;

	tls_error_clear(error);

	error->num = errnum;
	error->tls = 1;

	if (vasprintf(&errmsg, fmt, ap) == -1) {
		errmsg = NULL;
		goto err;
	}

	if (errnum == -1) {
		error->msg = errmsg;
		return (0);
	}

	if (asprintf(&error->msg, "%s: %s", errmsg, strerror(errnum)) == -1) {
		error->msg = NULL;
		goto err;
	}
	rv = 0;

 err:
	free(errmsg);

	return (rv);
}

int
tls_error_set(struct tls_error *error, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_error_setx(struct tls_error *error, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_config_set_error(struct tls_config *config, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(&config->error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_config_set_errorx(struct tls_config *config, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(&config->error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_set_error(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_set_errorx(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_set_ssl_errorx(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int rv;

	/* Only set an error if a more specific one does not already exist. */
	if (ctx->error.tls != 0)
		return (0);

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

struct tls_sni_ctx *
tls_sni_ctx_new(void)
{
	return (calloc(1, sizeof(struct tls_sni_ctx)));
}

void
tls_sni_ctx_free(struct tls_sni_ctx *sni_ctx)
{
	if (sni_ctx == NULL)
		return;

	SSL_CTX_free(sni_ctx->ssl_ctx);
	X509_free(sni_ctx->ssl_cert);

	free(sni_ctx);
}

struct tls *
tls_new(void)
{
	struct tls *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);

	ctx->config = tls_config_default;

	tls_reset(ctx);

	return (ctx);
}

int
tls_configure(struct tls *ctx, struct tls_config *config)
{
	if (config == NULL)
		config = tls_config_default;

	ctx->config = config;

	if ((ctx->flags & TLS_SERVER) != 0)
		return (tls_configure_server(ctx));

	return (0);
}

int
tls_configure_ssl_keypair(struct tls *ctx, SSL_CTX *ssl_ctx,
    struct tls_keypair *keypair, int required)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	BIO *bio = NULL;

	if (!required &&
	    keypair->cert_mem == NULL &&
	    keypair->key_mem == NULL)
		return(0);

	if (keypair->cert_mem != NULL) {
		if (keypair->cert_len > INT_MAX) {
			tls_set_errorx(ctx, "certificate too long");
			goto err;
		}

		if (SSL_CTX_use_certificate_chain_mem(ssl_ctx,
		    keypair->cert_mem, keypair->cert_len) != 1) {
			tls_set_errorx(ctx, "failed to load certificate");
			goto err;
		}
		cert = NULL;
	}
	if (keypair->key_mem != NULL) {
		if (keypair->key_len > INT_MAX) {
			tls_set_errorx(ctx, "key too long");
			goto err;
		}

		if ((bio = BIO_new_mem_buf(keypair->key_mem,
		    keypair->key_len)) == NULL) {
			tls_set_errorx(ctx, "failed to create buffer");
			goto err;
		}
		if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL,
		    NULL)) == NULL) {
			tls_set_errorx(ctx, "failed to read private key");
			goto err;
		}
		if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) {
			tls_set_errorx(ctx, "failed to load private key");
			goto err;
		}
		BIO_free(bio);
		bio = NULL;
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
		tls_set_errorx(ctx, "private/public key mismatch");
		goto err;
	}

	return (0);

 err:
	EVP_PKEY_free(pkey);
	X509_free(cert);
	BIO_free(bio);

	return (1);
}

int
tls_configure_ssl(struct tls *ctx, SSL_CTX *ssl_ctx)
{
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv3);

	SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TLSv1);
	SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
	SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TLSv1_2);

	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_0) == 0)
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_1) == 0)
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_2) == 0)
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);

	if (ctx->config->alpn != NULL) {
		if (SSL_CTX_set_alpn_protos(ssl_ctx, ctx->config->alpn,
		    ctx->config->alpn_len) != 0) {
			tls_set_errorx(ctx, "failed to set alpn");
			goto err;
		}
	}

	if (ctx->config->ciphers != NULL) {
		if (SSL_CTX_set_cipher_list(ssl_ctx,
		    ctx->config->ciphers) != 1) {
			tls_set_errorx(ctx, "failed to set ciphers");
			goto err;
		}
	}

	if (ctx->config->verify_time == 0) {
		X509_VERIFY_PARAM_set_flags(ssl_ctx->param,
		    X509_V_FLAG_NO_CHECK_TIME);
	}

	/* Disable any form of session caching by default */
	SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);

	return (0);

 err:
	return (-1);
}

static int
tls_ssl_cert_verify_cb(X509_STORE_CTX *x509_ctx, void *arg)
{
	struct tls *ctx = arg;
	int x509_err;

	if (ctx->config->verify_cert == 0)
		return (1);

	if ((X509_verify_cert(x509_ctx)) < 0) {
		tls_set_errorx(ctx, "X509 verify cert failed");
		return (0);
	}

	x509_err = X509_STORE_CTX_get_error(x509_ctx);
	if (x509_err == X509_V_OK)
		return (1);

	tls_set_errorx(ctx, "certificate verification failed: %s",
	    X509_verify_cert_error_string(x509_err));

	return (0);
}

int
tls_configure_ssl_verify(struct tls *ctx, SSL_CTX *ssl_ctx, int verify)
{
	size_t ca_len = ctx->config->ca_len;
	char *ca_mem = ctx->config->ca_mem;
	char *ca_free = NULL;
	int rv = -1;

	SSL_CTX_set_verify(ssl_ctx, verify, NULL);
	SSL_CTX_set_cert_verify_callback(ssl_ctx, tls_ssl_cert_verify_cb, ctx);

	if (ctx->config->verify_depth >= 0)
		SSL_CTX_set_verify_depth(ssl_ctx, ctx->config->verify_depth);

	if (ctx->config->verify_cert == 0)
		goto done;

	/* If no CA has been specified, attempt to load the default. */
	if (ctx->config->ca_mem == NULL && ctx->config->ca_path == NULL) {
		if (tls_config_load_file(&ctx->error, "CA", _PATH_SSL_CA_FILE,
		    &ca_mem, &ca_len) != 0)
			goto err;
		ca_free = ca_mem;
	}

	if (ca_mem != NULL) {
		if (ca_len > INT_MAX) {
			tls_set_errorx(ctx, "ca too long");
			goto err;
		}
		if (SSL_CTX_load_verify_mem(ssl_ctx, ca_mem, ca_len) != 1) {
			tls_set_errorx(ctx, "ssl verify memory setup failure");
			goto err;
		}
	} else if (SSL_CTX_load_verify_locations(ssl_ctx, NULL,
	    ctx->config->ca_path) != 1) {
		tls_set_errorx(ctx, "ssl verify locations failure");
		goto err;
	}

 done:
	rv = 0;

 err:
	free(ca_free);

	return (rv);
}

void
tls_free(struct tls *ctx)
{
	if (ctx == NULL)
		return;

	tls_reset(ctx);

	free(ctx);
}

void
tls_reset(struct tls *ctx)
{
	struct tls_sni_ctx *sni, *nsni;

	SSL_CTX_free(ctx->ssl_ctx);
	SSL_free(ctx->ssl_conn);
	X509_free(ctx->ssl_peer_cert);

	ctx->ssl_conn = NULL;
	ctx->ssl_ctx = NULL;
	ctx->ssl_peer_cert = NULL;

	ctx->socket = -1;
	ctx->state = 0;

	free(ctx->servername);
	ctx->servername = NULL;

	free(ctx->error.msg);
	ctx->error.msg = NULL;
	ctx->error.num = -1;

	tls_conninfo_free(ctx->conninfo);
	ctx->conninfo = NULL;

	tls_ocsp_free(ctx->ocsp);
	ctx->ocsp = NULL;

	for (sni = ctx->sni_ctx; sni != NULL; sni = nsni) {
		nsni = sni->next;
		tls_sni_ctx_free(sni);
	}
	ctx->sni_ctx = NULL;

	ctx->read_cb = NULL;
	ctx->write_cb = NULL;
	ctx->cb_arg = NULL;
}

int
tls_ssl_error(struct tls *ctx, SSL *ssl_conn, int ssl_ret, const char *prefix)
{
	const char *errstr = "unknown error";
	unsigned long err;
	int ssl_err;

	ssl_err = SSL_get_error(ssl_conn, ssl_ret);
	switch (ssl_err) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return (0);

	case SSL_ERROR_WANT_READ:
		return (TLS_WANT_POLLIN);

	case SSL_ERROR_WANT_WRITE:
		return (TLS_WANT_POLLOUT);

	case SSL_ERROR_SYSCALL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		} else if (ssl_ret == 0) {
			if ((ctx->state & TLS_HANDSHAKE_COMPLETE) != 0) {
				ctx->state |= TLS_EOF_NO_CLOSE_NOTIFY;
				return (0);
			}
			errstr = "unexpected EOF";
		} else if (ssl_ret == -1) {
			errstr = strerror(errno);
		}
		tls_set_ssl_errorx(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_SSL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		}
		tls_set_ssl_errorx(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_X509_LOOKUP:
	default:
		tls_set_ssl_errorx(ctx, "%s failed (%i)", prefix, ssl_err);
		return (-1);
	}
}

int
tls_handshake(struct tls *ctx)
{
	int rv = -1;

	tls_error_clear(&ctx->error);

	if ((ctx->flags & (TLS_CLIENT | TLS_SERVER_CONN)) == 0) {
		tls_set_errorx(ctx, "invalid operation for context");
		goto out;
	}

	if ((ctx->flags & TLS_CLIENT) != 0)
		rv = tls_handshake_client(ctx);
	else if ((ctx->flags & TLS_SERVER_CONN) != 0)
		rv = tls_handshake_server(ctx);

	if (rv == 0) {
		ctx->ssl_peer_cert = SSL_get_peer_certificate(ctx->ssl_conn);
		if (tls_conninfo_populate(ctx) == -1)
		    rv = -1;
		if (ctx->ocsp == NULL)
			ctx->ocsp = tls_ocsp_setup_from_peer(ctx);
	}
 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

ssize_t
tls_read(struct tls *ctx, void *buf, size_t buflen)
{
	ssize_t rv = -1;
	int ssl_ret;

	tls_error_clear(&ctx->error);

	if ((ctx->state & TLS_HANDSHAKE_COMPLETE) == 0) {
		if ((rv = tls_handshake(ctx)) != 0)
			goto out;
	}

	if (buflen > INT_MAX) {
		tls_set_errorx(ctx, "buflen too long");
		goto out;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_read(ctx->ssl_conn, buf, buflen)) > 0) {
		rv = (ssize_t)ssl_ret;
		goto out;
	}
	rv = (ssize_t)tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "read");

 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

ssize_t
tls_write(struct tls *ctx, const void *buf, size_t buflen)
{
	ssize_t rv = -1;
	int ssl_ret;

	tls_error_clear(&ctx->error);

	if ((ctx->state & TLS_HANDSHAKE_COMPLETE) == 0) {
		if ((rv = tls_handshake(ctx)) != 0)
			goto out;
	}

	if (buflen > INT_MAX) {
		tls_set_errorx(ctx, "buflen too long");
		goto out;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_write(ctx->ssl_conn, buf, buflen)) > 0) {
		rv = (ssize_t)ssl_ret;
		goto out;
	}
	rv = (ssize_t)tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "write");

 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

int
tls_close(struct tls *ctx)
{
	int ssl_ret;
	int rv = 0;

	tls_error_clear(&ctx->error);

	if ((ctx->flags & (TLS_CLIENT | TLS_SERVER_CONN)) == 0) {
		tls_set_errorx(ctx, "invalid operation for context");
		rv = -1;
		goto out;
	}

	if (ctx->state & TLS_SSL_NEEDS_SHUTDOWN) {
		ERR_clear_error();
		ssl_ret = SSL_shutdown(ctx->ssl_conn);
		if (ssl_ret < 0) {
			rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret,
			    "shutdown");
			if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT)
				goto out;
		}
		ctx->state &= ~TLS_SSL_NEEDS_SHUTDOWN;
	}

	if (ctx->socket != -1) {
		if (shutdown(ctx->socket, SHUT_RDWR) != 0) {
			if (rv == 0 &&
			    errno != ENOTCONN && errno != ECONNRESET) {
				tls_set_error(ctx, "shutdown");
				rv = -1;
			}
		}
		if (close(ctx->socket) != 0) {
			if (rv == 0) {
				tls_set_error(ctx, "close");
				rv = -1;
			}
		}
		ctx->socket = -1;
	}

	if ((ctx->state & TLS_EOF_NO_CLOSE_NOTIFY) != 0) {
		tls_set_errorx(ctx, "EOF without close notify");
		rv = -1;
	}

 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}
