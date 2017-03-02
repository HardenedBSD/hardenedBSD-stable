# $FreeBSD$

PROG=	bhyveload
SRCS=	bhyveload.c
MAN=	bhyveload.8
PACKAGE=	bhyve

CFI_OVERRIDE=-fno-sanitize=cfi-icall

LIBADD=	vmmapi

WARNS?=	3

CFLAGS+=-I${.CURDIR}/../../sys/boot/userboot

.include <bsd.prog.mk>
