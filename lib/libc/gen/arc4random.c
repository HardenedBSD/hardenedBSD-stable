/*	$OpenBSD: arc4random.c,v 1.24 2013/06/11 16:59:50 deraadt Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
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

/*
 * ChaCha based random number generator for OpenBSD.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "namespace.h"
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <pthread.h>

#include "libc_private.h"
#include "un-namespace.h"

#define KEYSTREAM_ONLY
#include "chacha_private.h"

#ifdef __GNUC__
#define inline __inline
#else				/* !__GNUC__ */
#define inline
#endif				/* !__GNUC__ */

static pthread_mutex_t	arc4random_mtx = PTHREAD_MUTEX_INITIALIZER;

#define	RANDOMDEV	"/dev/random"
#define	KEYSZ		32
#define	IVSZ		8
#define	BLOCKSZ		64
#define	RSBUFSZ		(16 * BLOCKSZ)
#define	_ARC4_LOCK()						\
	do {							\
		if (__isthreaded)				\
			_pthread_mutex_lock(&arc4random_mtx);	\
	} while (0)

#define	_ARC4_UNLOCK()						\
	do {							\
		if (__isthreaded)				\
			_pthread_mutex_unlock(&arc4random_mtx);	\
	} while (0)

/* Marked INHERIT_ZERO, so zero'd out in fork children. */
static struct {
	/* valid bytes at end of rs_buf */
	size_t		rs_have;
	/* bytes till reseed */
	size_t		rs_count;
} *rs;

/* Preserved in fork children */
static struct {
	/* chacha context for random keystream */
	chacha_ctx	ctx;		
	/* keystream blocks */	
	u_char		rs_buf[RSBUFSZ];
} *rsx;

extern int __sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
    void *newp, size_t newlen);

static inline void _rs_rekey(u_char *dat, size_t datlen);

static inline void
_rs_init(u_char *buf, size_t n)
{
	if (n < (KEYSZ+ IVSZ))
		return;

	if (rs == NULL) {
		if ((rs = mmap(NULL, sizeof(*rs), PROT_READ|PROT_WRITE,
			MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
			abort();

		if (minherit(rs, sizeof(*rs), INHERIT_ZERO) == -1) {
			munmap(rs, sizeof(*rs));
			abort();
		}

		if ((rsx = mmap(NULL, sizeof(*rsx), PROT_READ|PROT_WRITE,
			MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
			munmap(rs, sizeof(*rs));
			abort();
		}

		if (minherit(rsx, sizeof(*rsx), INHERIT_ZERO) == -1) {
			munmap(rsx, sizeof(*rsx));
			munmap(rs, sizeof(*rs));
			abort();
		}
	}

	chacha_keysetup(&rsx->ctx, buf, KEYSZ * 8, 0);
	chacha_ivsetup(&rsx->ctx, buf + KEYSZ);
}

static size_t
_rs_sysctl(u_char *buf, size_t size)
{
	int mib[2];
	size_t len, done;

	mib[0] = CTL_KERN;
	mib[1] = KERN_ARND;
	done = 0;

	do {
		len = size;
		if (__sysctl(mib, 2, buf, &len, NULL, 0) == -1)
			return (done);
		done += len;
		buf += len;
		size -= len;
	} while (size > 0);

	return (done);
}

static size_t
arc4_sysctl(u_char *buf, size_t size)
{
	return (_rs_sysctl(buf, size));
}

static void
_rs_stir(void)
{
	struct {
		struct timeval	tv;
		u_char		rnd[KEYSZ + IVSZ];
	} rdat;
	int done, fd;

	done = 0;
	if (_rs_sysctl((u_char *)&rdat, KEYSZ + IVSZ) == (KEYSZ + IVSZ))
		done = 1;

	if (!done) {
		fd = _open(RANDOMDEV, O_RDONLY | O_CLOEXEC, 0);
		if (fd >= 0) {
			if (_read(fd, &rdat, (KEYSZ + IVSZ)) == (KEYSZ + IVSZ))
				done = 1;
			(void)_close(fd);
		}
	}

	if (!done) {
		(void)gettimeofday(&rdat.tv, NULL);
		/* We'll just take whatever was on the stack too... */
	}

	if (!rs) {
		_rs_init((u_char *)&rdat, KEYSZ + IVSZ);
	} else {
		_rs_rekey((u_char *)&rdat, KEYSZ + IVSZ);
	}

	memset((u_char *)&rdat, 0, sizeof(rdat));

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, RSBUFSZ);

	rs->rs_count = 1600000;
}

static inline void
_rs_stir_if_needed(size_t len)
{
	if (!rs || rs->rs_count <= len)
		_rs_stir();
	else	
		rs->rs_count -= len;
}

static inline void
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, RSBUFSZ);
#endif

	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->ctx, rsx->rs_buf, rsx->rs_buf, RSBUFSZ);
	/* mix in optional user provided data */
	if (dat) {
		size_t i, m;

		m = MIN(datlen, (KEYSZ + IVSZ));
		for (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediatly reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, (KEYSZ + IVSZ));
	memset(rsx->rs_buf, 0, (KEYSZ + IVSZ));
	rs->rs_have = (RSBUFSZ - KEYSZ - IVSZ);
}

static inline void
_rs_random_buf(void *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	size_t m;

	_rs_stir_if_needed(n);
	while (n > 0) {
		if (rs->rs_have > 0) {
			m = MIN(n, rs->rs_have);
			keystream = (rsx->rs_buf + RSBUFSZ - rs->rs_have);
			memcpy(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}

		if (rs->rs_have == 0)
			_rs_rekey(NULL, 0);
	}
}

static inline void
_rs_random_u32(u_int32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(sizeof(*val));
	if (rs->rs_have < sizeof(*val))
		_rs_rekey(NULL, 0);
	keystream = (rsx->rs_buf + RSBUFSZ - rs->rs_have);
	memcpy(val, keystream, sizeof(*val));
	memset(keystream, 0, sizeof(*val));
	rs->rs_have -= sizeof(*val);
}

void
arc4random_addrandom(u_char *dat, int datlen)
{
	int m;

	_ARC4_LOCK();
	if (!rs)
		_rs_stir();

	while (datlen > 0) {
		m = MIN(datlen, (KEYSZ + IVSZ));
		_rs_rekey(dat, m);
		dat += m;
		datlen -= m;
	}
	_ARC4_UNLOCK();
}

u_int32_t
arc4random(void)
{
	u_int32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	return val;
}

void
arc4random_buf(void *_buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(_buf, n);
	_ARC4_UNLOCK();
}

void
arc4random_stir(void)
{
	_ARC4_LOCK();
	_rs_stir();
	_ARC4_UNLOCK();
}

u_int32_t
arc4random_uniform(u_int32_t upper_bound)
{
	u_int32_t r, min;

	if (upper_bound < 2)
		return (0);

	/* 2**32 % x == (2**32 - x) % x */
	min = -upper_bound % upper_bound;

	/*
	 * This could theorically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */

	for (;;) {
		r = arc4random();
		if (r >= min)
			break;
	}

	return (r % upper_bound);
}

#if 0
/*-------- Test code for i386 --------*/
#include <stdio.h>
#include <machine/pctr.h>
int
main(int argc, char **argv)
{
	const int iter = 1000000;
	int     i;
	pctrval v;

	v = rdtsc();
	for (i = 0; i < iter; i++)
		arc4random();
	v = rdtsc() - v;
	v /= iter;

	printf("%qd cycles\n", v);
}
#endif
