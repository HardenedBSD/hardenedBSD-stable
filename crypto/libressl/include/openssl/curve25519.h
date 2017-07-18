/*
 * Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HEADER_CURVE25519_H
#define HEADER_CURVE25519_H

#include <stdint.h>

#include <openssl/opensslconf.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * Curve25519.
 *
 * Curve25519 is an elliptic curve. See https://tools.ietf.org/html/rfc7748.
 */

/*
 * X25519.
 *
 * X25519 is the Diffie-Hellman primitive built from curve25519. It is
 * sometimes referred to as curve25519, but X25519 is a more precise name.
 * See http://cr.yp.to/ecdh.html and https://tools.ietf.org/html/rfc7748.
 */

#define X25519_KEY_LENGTH 32

/*
 * X25519_keypair sets |out_public_value| and |out_private_key| to a freshly
 * generated, public/private key pair.
 */
void X25519_keypair(uint8_t out_public_value[X25519_KEY_LENGTH],
    uint8_t out_private_key[X25519_KEY_LENGTH]);

/*
 * X25519 writes a shared key to |out_shared_key| that is calculated from the
 * given private key and the peer's public value. It returns one on success and
 * zero on error.
 *
 * Don't use the shared key directly, rather use a KDF and also include the two
 * public values as inputs.
 */
int X25519(uint8_t out_shared_key[X25519_KEY_LENGTH],
    const uint8_t private_key[X25519_KEY_LENGTH],
    const uint8_t peers_public_value[X25519_KEY_LENGTH]);

#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* HEADER_CURVE25519_H */
