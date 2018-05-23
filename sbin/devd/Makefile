# $FreeBSD$

.include <src.opts.mk>

PACKAGE=runtime
PROG_CXX=devd
SRCS=	devd.cc token.l parse.y y.tab.h
MAN=	devd.8 devd.conf.5

<<<<<<< HEAD
YFLAGS=-dvi

.if ${MK_DEVD_PIE} == "no"
=======
>>>>>>> origin/freebsd/current/master
NO_SHARED?=YES
.endif

LIBADD=	l util

YFLAGS+=-v
CFLAGS+=-I. -I${.CURDIR}
CFLAGS.clang += -Wno-missing-variable-declarations
CFLAGS.gcc = -Wno-redundant-decls
CXXFLAGS.gcc = -Wno-redundant-decls

CLEANFILES= y.output y.tab.i

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
