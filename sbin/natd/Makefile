# $FreeBSD$

PROG		= natd
SRCS		= natd.c icmp.c
WARNS?=	3
LDADD		= -lalias
DPADD		= ${LIBALIAS}
MAN		= natd.8

CAN_PIE=1

.include <bsd.prog.mk>
