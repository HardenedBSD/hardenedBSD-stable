# $FreeBSD$

PROG=		iscsid
SRCS=		chap.c discovery.c iscsid.c keys.c log.c login.c pdu.c
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${.CURDIR}/../../sys/cam
CFLAGS+=	-I${.CURDIR}/../../sys/dev/iscsi
#CFLAGS+=	-DICL_KERNEL_PROXY
MAN=		iscsid.8

<<<<<<< HEAD
DPADD=		${LIBCRYPTO} ${LIBSSL} ${LIBUTIL}
LDADD=		-lcrypto -lssl -lutil
WANTS_PIE=	yes
=======
DPADD=		${LIBMD} ${LIBUTIL}
LDADD=		-lmd -lutil
>>>>>>> origin/stable/10

WARNS=		6

.include <bsd.prog.mk>
