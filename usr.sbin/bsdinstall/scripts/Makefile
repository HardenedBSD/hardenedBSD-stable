# $FreeBSD$

<<<<<<< HEAD
.include <src.opts.mk>

SCRIPTS= auto adduser checksum config docsinstall entropy hardening hostname jail \
	 keymap mirrorselect mount netconfig netconfig_ipv4 netconfig_ipv6 \
	 rootpass script services time umount wlanconfig zfsboot
=======
SCRIPTS= auto adduser bootconfig checksum config docsinstall entropy hardening \
	 hostname jail keymap mirrorselect mount netconfig netconfig_ipv4 \
	 netconfig_ipv6 rootpass script services time umount wlanconfig \
	 zfsboot
>>>>>>> origin/freebsd/current/master
BINDIR= ${LIBEXECDIR}/bsdinstall

MAN=

services!
.if ${MK_OPENNTPD} == "no"
	${CP} ${.CURDIR}/services.iscntpd ${.CURDIR}/services
.else
	${CP} ${.CURDIR}/services.openntpd ${.CURDIR}/services
.endif

.include <bsd.prog.mk>
