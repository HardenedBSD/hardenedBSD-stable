#	$OpenBSD: Makefile,v 1.22 2015/10/07 23:33:38 beck Exp $

.include "../libcrypto/Makefile.inc.libressl"

CFLAGS+= -Wall -Werror -Wimplicit

LIB=	tls
SHLIB_MAJOR=	10

LTLS_SRC=	${LIBRESSL_SRC}/tls

LIBADD= crypto ssl

INCS=	tls.h

SRCS=	tls.c \
	tls_client.c \
	tls_config.c \
	tls_conninfo.c \
	tls_peer.c \
	tls_server.c \
	tls_util.c \
	tls_verify.c

.PATH: ${LTLS_SRC} \
	${LIBRESSL_SRC}/include

.include <bsd.lib.mk>
