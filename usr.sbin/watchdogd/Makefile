# $FreeBSD$

PROG=	watchdogd
LINKS=	${BINDIR}/watchdogd ${BINDIR}/watchdog
MAN=	watchdogd.8 watchdog.8

CAN_PIE=1

LDADD=	-lutil
DPADD=	${LIBUTIL}

.include <bsd.prog.mk>

test:	${PROG}
	./${PROG} -t 1.0
