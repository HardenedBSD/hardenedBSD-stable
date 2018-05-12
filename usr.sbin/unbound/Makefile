# $FreeBSD$
.include <src.opts.mk>

<<<<<<< HEAD
SUBDIR=	daemon anchor checkconf control host
SUBDIR+= local-setup
=======
SUBDIR=	daemon anchor checkconf control
SUBDIR+= setup
>>>>>>> origin/freebsd/current/master
SUBDIR_PARALLEL=

.if ${MK_LIBRESSL} != "no"
CFLAGS+= -DHAVE_LIBRESSL=1
.endif

.include <bsd.subdir.mk>
