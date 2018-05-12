# $FreeBSD$

# Vendor sources and generated files
LDNSDIR= ${SRCTOP}/contrib/ldns
UNBOUNDDIR= ${SRCTOP}/contrib/unbound

.PATH: ${UNBOUNDDIR} ${UNBOUNDDIR}/smallapp ${UNBOUNDDIR}/util ${UNBOUNDDIR}/doc

PROG=	local-unbound-checkconf
SRCS=	ub_event.c unbound-checkconf.c worker_cb.c
CFLAGS+=	-I${UNBOUNDDIR} -I${LDNSDIR}
LIBADD=	unbound pthread
<<<<<<< HEAD
MAN=	unbound-checkconf.8
CFI_OVERRIDE=-fno-sanitize=cfi-icall
=======
MAN=	local-unbound-checkconf.8
>>>>>>> origin/freebsd/current/master

.include <bsd.prog.mk>
