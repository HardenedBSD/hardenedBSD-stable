# $FreeBSD$

PROG		= natd
SRCS		= natd.c icmp.c
WARNS?=	3
LDADD		= -lalias
DPADD		= ${LIBALIAS}
WANTS_PIE	= yes
MAN		= natd.8

.include <bsd.prog.mk>
