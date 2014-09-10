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
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/sbuf.h>
#include <sys/jail.h>
#include <machine/stdarg.h>

#define __PAX_LOG_TEMPLATE(SUBJECT, name)					\
void										\
pax_log_##name(struct proc *p, const char *caller_name, 		\
		const char* fmt, ...)			\
{										\
	struct sbuf *sb;							\
	va_list args;								\
	bool w_locked;						\
										\
	if (pax_log_log == 0)							\
		return;								\
	sx_slock(&proctree_lock);			\
	if ((w_locked = PROC_LOCKED(p)))	\
		PROC_UNLOCK(p);					\
										\
	sb = sbuf_new_auto();							\
	if (sb == NULL)								\
		panic("%s: Could not allocate memory", __func__);		\
	sbuf_printf(sb, "[PAX "#SUBJECT"] ");					\
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
	if (w_locked && !PROC_LOCKED(p))			\
		PROC_LOCK(p);					\
	sx_sunlock(&proctree_lock);			\
}										\
										\
void										\
pax_ulog_##name(const char *caller_name, const char* fmt, ...)			\
{										\
	struct sbuf *sb;							\
	va_list args;								\
	struct thread *td;					\
	bool w_locked;						\
										\
	if (pax_log_ulog == 0)							\
		return;								\
	sx_slock(&proctree_lock);		\
	td = curthread;					\
	if ((w_locked = PROC_LOCKED(td->td_proc)))			\
		PROC_UNLOCK(td->td_proc);					\
										\
	sb = sbuf_new_auto();							\
	if (sb == NULL)								\
		panic("%s: Could not allocate memory", __func__);		\
	sbuf_printf(sb, "[PAX "#SUBJECT"] ");					\
	if (caller_name != NULL)						\
		sbuf_printf(sb, "%s: ", caller_name);				\
	va_start(args, fmt);							\
	sbuf_vprintf(sb, fmt, args);						\
	va_end(args);								\
	if (sbuf_finish(sb) != 0)						\
		panic("%s: Could not generate message", __func__);		\
										\
	uprintf("%s", sbuf_data(sb));						\
	sbuf_delete(sb);					\
	if (w_locked && !PROC_LOCKED(td->td_proc))						\
		PROC_LOCK(td->td_proc);						\
	sx_sunlock(&proctree_lock);			\
}


static int sysctl_pax_log_log(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_log_ulog(SYSCTL_HANDLER_ARGS);

int pax_log_log = PAX_LOG_LOG;
int pax_log_ulog = PAX_LOG_ULOG;

TUNABLE_INT("hardening.log.log", &pax_log_log);
TUNABLE_INT("hardening.log.ulog", &pax_log_ulog);

#ifdef PAX_SYSCTLS
SYSCTL_NODE(_hardening, OID_AUTO, log, CTLFLAG_RD, 0,
    "Hardening related logging facility.");

SYSCTL_PROC(_hardening_log, OID_AUTO, log,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_log_log, "I",
    "log to syslog "
    "0 - disabled, "
    "1 - enabled ");

SYSCTL_PROC(_hardening_log, OID_AUTO, ulog,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_log_ulog, "I",
    "log to user terminal"
    "0 - disabled, "
    "1 - enabled ");
#endif

static void
pax_log_sysinit(void)
{
	printf("[PAX LOG] logging to system: %d\n", pax_log_log);
	printf("[PAX LOG] logging to user: %d\n", pax_log_ulog);
}
SYSINIT(pax_log, SI_SUB_PAX, SI_ORDER_SECOND, pax_log_sysinit, NULL);

#ifdef PAX_SYSCTLS
static int
sysctl_pax_log_log(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;

	val = pax_log_log;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || !req->newptr)
		return (err);

	switch (val) {
	case	0:
	case	1:
		break;
	default:
		return (EINVAL);

	}

	pax_log_log = val;

	return (0);
}

static int
sysctl_pax_log_ulog(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;

	val = pax_log_ulog;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || !req->newptr)
		return (err);

	switch (val) {
	case	0:
	case	1:
		break;
	default:
		return (EINVAL);

	}

	pax_log_ulog = val;

	return (0);
}
#endif

__PAX_LOG_TEMPLATE(ASLR, aslr)
