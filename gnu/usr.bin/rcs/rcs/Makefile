# $FreeBSD$

PROG=	rcs
MAN=	rcs.1 rcsintro.1 rcsfile.5
CFLAGS+= -I${.CURDIR}/../lib
LDADD=  ${LIBRCS}
DPADD=  ${LIBRCS}

NO_PIE=yes

.include "../../Makefile.inc"
.include <bsd.prog.mk>
