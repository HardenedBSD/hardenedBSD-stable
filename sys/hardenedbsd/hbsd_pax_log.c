/*-
 * Copyright (c) 2014, by Oliver Pinter <oliver.pntr at gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include "opt_pax.h"

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/jail.h>
#include <machine/stdarg.h>

#define __HARDENING_LOG_TEMPLATE(MAIN, SUBJECT, prefix, name)			\
void										\
prefix##_log_##name(struct proc *p, const char *caller_name, 			\
		const char* fmt, ...)						\
{										\
	struct sbuf *sb;							\
	va_list args;								\
										\
	if (hardening_log_log == 0)						\
		return;								\
										\
	sb = sbuf_new_auto();							\
	if (sb == NULL)								\
		panic("%s: Could not allocate memory", __func__);		\
	sbuf_printf(sb, "["#MAIN" "#SUBJECT"] ");				\
	if (caller_name != NULL)						\
		sbuf_printf(sb, "%s: ", caller_name);				\
	va_start(args, fmt);							\
	sbuf_vprintf(sb, fmt, args);						\
	va_end(args);								\
	if (sbuf_finish(sb) != 0)						\
		panic("%s: Could not generate message", __func__);		\
										\
	printf("%s", sbuf_data(sb));						\
	sbuf_delete(sb);							\
}										\
										\
void										\
prefix##_ulog_##name(const char *caller_name, const char* fmt, ...)		\
{										\
	struct sbuf *sb;							\
	va_list args;								\
										\
	if (hardening_log_ulog == 0)						\
		return;								\
										\
	sb = sbuf_new_auto();							\
	if (sb == NULL)								\
		panic("%s: Could not allocate memory", __func__);		\
	sbuf_printf(sb, "["#MAIN" "#SUBJECT"] ");				\
	if (caller_name != NULL)						\
		sbuf_printf(sb, "%s: ", caller_name);				\
	va_start(args, fmt);							\
	sbuf_vprintf(sb, fmt, args);						\
	va_end(args);								\
	if (sbuf_finish(sb) != 0)						\
		panic("%s: Could not generate message", __func__);		\
										\
	hbsd_uprintf("%s", sbuf_data(sb));					\
	sbuf_delete(sb);							\
}


static int sysctl_hardening_log_log(SYSCTL_HANDLER_ARGS);
static int sysctl_hardening_log_ulog(SYSCTL_HANDLER_ARGS);

int hardening_log_log = HARDENING_LOG_LOG;
int hardening_log_ulog = HARDENING_LOG_ULOG;

TUNABLE_INT("hardening.log.log", &hardening_log_log);
TUNABLE_INT("hardening.log.ulog", &hardening_log_ulog);

#ifdef PAX_SYSCTLS
SYSCTL_NODE(_hardening, OID_AUTO, log, CTLFLAG_RD, 0,
    "Hardening related logging facility.");

SYSCTL_PROC(_hardening_log, OID_AUTO, log,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_hardening_log_log, "I",
    "log to syslog "
    "0 - disabled, "
    "1 - enabled ");

SYSCTL_PROC(_hardening_log, OID_AUTO, ulog,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_hardening_log_ulog, "I",
    "log to user terminal"
    "0 - disabled, "
    "1 - enabled ");
#endif


static void
hardening_log_sysinit(void)
{
	switch (hardening_log_log) {
	case PAX_FEATURE_SIMPLE_DISABLED:
	case PAX_FEATURE_SIMPLE_ENABLED:
		break;
	default:
		printf("[HARDENING LOG] WARNING, invalid settings in loader.conf!"
		    " (hardening.log.log = %d)\n", hardening_log_log);
		hardening_log_log = PAX_FEATURE_SIMPLE_ENABLED;
	}
	printf("[HARDENING LOG] logging to system: %s\n",
	    pax_status_simple_str[hardening_log_log]);

	switch (hardening_log_ulog) {
	case PAX_FEATURE_SIMPLE_DISABLED:
	case PAX_FEATURE_SIMPLE_ENABLED:
		break;
	default:
		printf("[HARDENING LOG] WARNING, invalid settings in loader.conf!"
		    " (hardening.log.ulog = %d)\n", hardening_log_ulog);
		hardening_log_ulog = PAX_FEATURE_SIMPLE_ENABLED;
	}
	printf("[HARDENING LOG] logging to user: %s\n",
	    pax_status_simple_str[hardening_log_ulog]);
}
SYSINIT(hardening_log, SI_SUB_PAX, SI_ORDER_SECOND, hardening_log_sysinit, NULL);

#ifdef PAX_SYSCTLS
static int
sysctl_hardening_log_log(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;

	val = hardening_log_log;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || !req->newptr)
		return (err);

	switch (val) {
	case	PAX_FEATURE_SIMPLE_DISABLED :
	case	PAX_FEATURE_SIMPLE_ENABLED :
		break;
	default:
		return (EINVAL);

	}

	hardening_log_log = val;

	return (0);
}

static int
sysctl_hardening_log_ulog(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;

	val = hardening_log_ulog;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || !req->newptr)
		return (err);

	switch (val) {
	case	PAX_FEATURE_SIMPLE_DISABLED :
	case	PAX_FEATURE_SIMPLE_ENABLED :
		break;
	default:
		return (EINVAL);

	}

	hardening_log_ulog = val;

	return (0);
}
#endif

__HARDENING_LOG_TEMPLATE(PAX, ASLR, pax, aslr);
__HARDENING_LOG_TEMPLATE(PAX, SEGVGUARD, pax, segvguard);
__HARDENING_LOG_TEMPLATE(PAX, PTRACE_HARDENING, pax, ptrace_hardening);
