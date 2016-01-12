#
# $FreeBSD$
#

PROG=	bhyvectl
SRCS=	bhyvectl.c

MAN=	bhyvectl.8

LIBADD=	vmmapi util
WANTS_PIE=	yes

WARNS?=	3

CFLAGS+= -I${.CURDIR}/../../sys/amd64/vmm

.include <bsd.prog.mk>
