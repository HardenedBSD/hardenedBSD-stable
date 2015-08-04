# $FreeBSD$

PROG=		iscsid
SRCS=		chap.c discovery.c iscsid.c keys.c log.c login.c pdu.c
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${.CURDIR}/../../sys/cam
CFLAGS+=	-I${.CURDIR}/../../sys/dev/iscsi
#CFLAGS+=	-DICL_KERNEL_PROXY
MAN=		iscsid.8

WANTS_PIE=	yes

DPADD=		${LIBMD} ${LIBUTIL}
LDADD=		-lmd -lutil

WARNS=		6

.include <bsd.prog.mk>
