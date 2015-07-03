# $FreeBSD$

PROG=		iscsid
SRCS=		chap.c discovery.c iscsid.c keys.c log.c login.c pdu.c
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${.CURDIR}/../../sys/cam
CFLAGS+=	-I${.CURDIR}/../../sys/dev/iscsi
#CFLAGS+=	-DICL_KERNEL_PROXY
MAN=		iscsid.8

<<<<<<< HEAD
LIBADD=		crypto util
WANTS_PIE=	yes
=======
LIBADD=		md util
>>>>>>> origin/master

WARNS=		6

.include <bsd.prog.mk>
