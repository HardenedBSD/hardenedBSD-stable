# Vendor sources and generated files
LDNSDIR= ${.CURDIR}/../../../contrib/ldns
UNBOUNDDIR= ${.CURDIR}/../../../contrib/unbound

.PATH: ${UNBOUNDDIR} ${UNBOUNDDIR}/smallapp ${UNBOUNDDIR}/doc

PROG=	unbound-host
SRCS=	unbound-host.c
CFLAGS+=	-I${UNBOUNDDIR} -I${LDNSDIR}
DPADD=	${LIBUNBOUND} ${LIBCRYPTO} ${LIBSSL} ${LIBPTHREAD}
LDADD=	-lunbound -lcrypto -lssl -lpthread
USEPRIVATELIB=
MAN=	unbound-host.1

.include <bsd.prog.mk>
