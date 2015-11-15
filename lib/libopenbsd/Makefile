# $FreeBSD$

LIB=	openbsd
SRCS=	getdtablecount.c \
	imsg-buffer.c \
	imsg.c \
	ohash.c
INTERNALLIB=

<<<<<<< HEAD
.if defined(NO_SHARED)
.if ${NO_SHARED} == "no" || ${NO_SHARED} == "NO"
CFLAGS+= -fPIC
.endif
.else
CFLAGS+= -fPIC
.endif
=======
CFLAGS+= -I${.CURDIR}
>>>>>>> origin/master

WARNS=	3

NO_WERROR=
.include <bsd.lib.mk>
