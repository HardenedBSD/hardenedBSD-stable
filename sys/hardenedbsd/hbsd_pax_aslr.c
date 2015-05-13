/*-
 * Copyright (c) 2006 Elad Efrat <elad@NetBSD.org>
 * Copyright (c) 2013-2015, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
 * Copyright (c) 2014-2015, by Shawn Webb <shawn.webb@hardenedbsd.org>
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"
#include "opt_pax.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/elf_common.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/kthread.h>
#include <sys/ktr.h>
#include <sys/libkern.h>
#include <sys/libkern.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/vnode.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>

#include <machine/elf.h>

#ifndef PAX_ASLR_DELTA
#define	PAX_ASLR_DELTA(delta, lsb, len)	\
	(((delta) & ((1UL << (len)) - 1)) << (lsb))
#endif /* PAX_ASLR_DELTA */

/*-
 * generic ASLR values
 *
 *  	MMAP	| 32 bit | 64 bit | compat |
 * 	+-------+--------+--------+--------+
 * 	| MIN	|  8 bit | 16 bit |  8 bit |
 * 	+-------+--------+--------+--------+
 * 	| DEF	| 14 bit | 30 bit | 14 bit |
 * 	+-------+--------+--------+--------+
 * 	| MAX   | 21 bit | 42 bit | 21 bit |
 * 	+-------+--------+--------+--------+
 *                                          
 *  	STACK	| 32 bit | 64 bit | 32 bit |
 * 	+-------+--------+--------+--------+
 * 	| MIN	|  8 bit | 16 bit |  8 bit |
 * 	+-------+--------+--------+--------+
 * 	| DEF	|  8 bit | 26 bit |  8 bit |
 * 	+-------+--------+--------+--------+
 * 	| MAX   | 21 bit | 42 bit | 21 bit |
 * 	+-------+--------+--------+--------+
 *                                          
 *  	EXEC	| 32 bit | 64 bit | 32 bit |
 * 	+-------+--------+--------+--------+
 * 	| MIN	|  8 bit | 16 bit |  8 bit |
 * 	+-------+--------+--------+--------+
 * 	| DEF	| 14 bit | 21 bit | 14 bit |
 * 	+-------+--------+--------+--------+
 * 	| MAX   | 21 bit | 42 bit | 21 bit |
 * 	+-------+--------+--------+--------+
 *
 */
#ifndef PAX_ASLR_DELTA_MMAP_LSB
#define PAX_ASLR_DELTA_MMAP_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_DELTA_MMAP_LSB */

#ifndef PAX_ASLR_DELTA_MMAP_MIN_LEN
#define PAX_ASLR_DELTA_MMAP_MIN_LEN	((sizeof(void *) * NBBY) / 4)
#endif /* PAX_ASLR_DELTA_MMAP_MAX_LEN */

#ifndef PAX_ASLR_DELTA_MMAP_MAX_LEN
#define PAX_ASLR_DELTA_MMAP_MAX_LEN	(((sizeof(void *) * NBBY) * 2) / 3)
#endif /* PAX_ASLR_DELTA_MMAP_MAX_LEN */

#ifndef PAX_ASLR_DELTA_STACK_LSB
#define PAX_ASLR_DELTA_STACK_LSB	3
#endif /* PAX_ASLR_DELTA_STACK_LSB */

#ifndef PAX_ASLR_DELTA_STACK_MIN_LEN
#define PAX_ASLR_DELTA_STACK_MIN_LEN	((sizeof(void *) * NBBY) / 4)
#endif /* PAX_ASLR_DELTA_STACK_MAX_LEN */

#ifndef PAX_ASLR_DELTA_STACK_MAX_LEN
#define PAX_ASLR_DELTA_STACK_MAX_LEN	(((sizeof(void *) * NBBY) * 2) / 3)
#endif /* PAX_ASLR_DELTA_STACK_MAX_LEN */

#ifndef PAX_ASLR_DELTA_EXEC_LSB
#define PAX_ASLR_DELTA_EXEC_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_DELTA_EXEC_LSB */

#ifndef PAX_ASLR_DELTA_EXEC_MIN_LEN
#define PAX_ASLR_DELTA_EXEC_MIN_LEN	((sizeof(void *) * NBBY) / 4)
#endif /* PAX_ASLR_DELTA_EXEC_MIN_LEN */

#ifndef PAX_ASLR_DELTA_EXEC_MAX_LEN
#define PAX_ASLR_DELTA_EXEC_MAX_LEN	(((sizeof(void *) * NBBY) * 2) / 3)
#endif /* PAX_ASLR_DELTA_EXEC_MAX_LEN */

/*
 * ASLR default values for native host
 */
#ifdef __LP64__
#ifndef PAX_ASLR_DELTA_MMAP_DEF_LEN
#define PAX_ASLR_DELTA_MMAP_DEF_LEN	30
#endif /* PAX_ASLR_DELTA_MMAP_DEF_LEN */
#ifndef PAX_ASLR_DELTA_STACK_DEF_LEN
#define PAX_ASLR_DELTA_STACK_DEF_LEN	26
#endif /* PAX_ASLR_DELTA_STACK_DEF_LEN */
#ifndef PAX_ASLR_DELTA_EXEC_DEF_LEN
#define PAX_ASLR_DELTA_EXEC_DEF_LEN	21
#endif /* PAX_ASLR_DELTA_EXEC_DEF_LEN */
#else /* ! __LP64__ */
#ifndef PAX_ASLR_DELTA_MMAP_DEF_LEN
#define PAX_ASLR_DELTA_MMAP_DEF_LEN	14
#endif /* PAX_ASLR_DELTA_MMAP_DEF_LEN */
#ifndef PAX_ASLR_DELTA_STACK_DEF_LEN
#define PAX_ASLR_DELTA_STACK_DEF_LEN	PAX_ASLR_DELTA_STACK_MIN_LEN
#endif /* PAX_ASLR_DELTA_STACK_DEF_LEN */
#ifndef PAX_ASLR_DELTA_EXEC_DEF_LEN
#define PAX_ASLR_DELTA_EXEC_DEF_LEN	14
#endif /* PAX_ASLR_DELTA_EXEC_DEF_LEN */
#endif /* __LP64__ */

/*
 * ASLR values for COMPAT_FREEBSD32, COMPAT_LINUX and MAP_32BIT
 */
#if defined(COMPAT_LINUX) || defined(COMPAT_FREEBSD32) || defined(MAP_32BIT)
#ifndef PAX_ASLR_COMPAT_DELTA_MMAP_LSB
#define PAX_ASLR_COMPAT_DELTA_MMAP_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_COMPAT_DELTA_MMAP_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_MMAP_MIN_LEN
#define PAX_ASLR_COMPAT_DELTA_MMAP_MIN_LEN	((sizeof(int) * NBBY) / 4)
#endif /* PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN
#define PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN	(((sizeof(int) * NBBY) * 2) / 3)
#endif /* PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_STACK_LSB
#define PAX_ASLR_COMPAT_DELTA_STACK_LSB		3
#endif /* PAX_ASLR_COMPAT_DELTA_STACK_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_STACK_MIN_LEN
#define PAX_ASLR_COMPAT_DELTA_STACK_MIN_LEN	((sizeof(int) * NBBY) / 4)
#endif /* PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN
#define PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN	(((sizeof(int) * NBBY) * 2) / 3)
#endif /* PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_EXEC_LSB
#define PAX_ASLR_COMPAT_DELTA_EXEC_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_COMPAT_DELTA_EXEC_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_EXEC_MIN_LEN
#define PAX_ASLR_COMPAT_DELTA_EXEC_MIN_LEN	((sizeof(int) * NBBY) / 4)
#endif /* PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN
#define PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN	(((sizeof(int) * NBBY) * 2) / 3)
#endif /* PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN */
#endif

FEATURE(aslr, "Address Space Layout Randomization.");

static int pax_aslr_status = PAX_FEATURE_OPTOUT;
static int pax_aslr_mmap_len = PAX_ASLR_DELTA_MMAP_DEF_LEN;
static int pax_aslr_stack_len = PAX_ASLR_DELTA_STACK_DEF_LEN;
static int pax_aslr_exec_len = PAX_ASLR_DELTA_EXEC_DEF_LEN;

#ifdef COMPAT_FREEBSD32
static int pax_aslr_compat_status = PAX_FEATURE_OPTOUT;
static int pax_aslr_compat_mmap_len = PAX_ASLR_COMPAT_DELTA_MMAP_MIN_LEN;
static int pax_aslr_compat_stack_len = PAX_ASLR_COMPAT_DELTA_STACK_MIN_LEN;
static int pax_aslr_compat_exec_len = PAX_ASLR_COMPAT_DELTA_EXEC_MIN_LEN;
#endif /* COMPAT_FREEBSD32 */

TUNABLE_INT("hardening.pax.aslr.status", &pax_aslr_status);
TUNABLE_INT("hardening.pax.aslr.mmap_len", &pax_aslr_mmap_len);
TUNABLE_INT("hardening.pax.aslr.stack_len", &pax_aslr_stack_len);
TUNABLE_INT("hardening.pax.aslr.exec_len", &pax_aslr_exec_len);
#ifdef COMPAT_FREEBSD32
TUNABLE_INT("hardening.pax.aslr.compat.status", &pax_aslr_compat_status);
TUNABLE_INT("hardening.pax.aslr.compat.mmap_len", &pax_aslr_compat_mmap_len);
TUNABLE_INT("hardening.pax.aslr.compat.stack_len", &pax_aslr_compat_stack_len);
TUNABLE_INT("hardening.pax.aslr.compat.exec_len", &pax_aslr_compat_exec_len);
#endif

#ifdef PAX_SYSCTLS
SYSCTL_DECL(_hardening_pax);

/*
 * sysctls
 */
static int sysctl_pax_aslr_status(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_mmap(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_stack(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_exec(SYSCTL_HANDLER_ARGS);


SYSCTL_NODE(_hardening_pax, OID_AUTO, aslr, CTLFLAG_RD, 0,
    "Address Space Layout Randomization.");

SYSCTL_PROC(_hardening_pax_aslr, OID_AUTO, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_aslr_status, "I",
    "Restrictions status. "
    "0 - disabled, "
    "1 - opt-in,  "
    "2 - opt-out, "
    "3 - force enabled");

SYSCTL_PROC(_hardening_pax_aslr, OID_AUTO, mmap_len,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_aslr_mmap, "I",
    "Number of bits randomized for mmap(2) calls. "
    "32 bit: [8,20] 64 bit: [16,32]");

SYSCTL_PROC(_hardening_pax_aslr, OID_AUTO, stack_len,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_aslr_stack, "I",
    "Number of bits randomized for the stack. "
    "32 bit: [6,12] 64 bit: [12,21]");

SYSCTL_PROC(_hardening_pax_aslr, OID_AUTO, exec_len,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_aslr_exec, "I",
    "Number of bits randomized for the PIE exec base. "
    "32 bit: [6,20] 64 bit: [12,21]");

static int
sysctl_pax_aslr_status(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hardening.hr_pax_aslr_status;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	switch (val) {
	case PAX_FEATURE_DISABLED:
	case PAX_FEATURE_OPTIN:
	case PAX_FEATURE_OPTOUT:
	case PAX_FEATURE_FORCE_ENABLED:
		if (pr == &prison0)
			pax_aslr_status = val;

		pr->pr_hardening.hr_pax_aslr_status = val;
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

static int
sysctl_pax_aslr_mmap(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hardening.hr_pax_aslr_mmap_len;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || !req->newptr)
		return (err);

	if (val < PAX_ASLR_DELTA_MMAP_MIN_LEN ||
	    val > PAX_ASLR_DELTA_MMAP_MAX_LEN)
		return (EINVAL);

	if (pr == &prison0)
		pax_aslr_mmap_len = val;

	pr->pr_hardening.hr_pax_aslr_mmap_len = val;

	return (0);
}

static int
sysctl_pax_aslr_stack(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hardening.hr_pax_aslr_stack_len;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || !req->newptr)
		return (err);

	if (val < PAX_ASLR_DELTA_STACK_MIN_LEN ||
	    val > PAX_ASLR_DELTA_STACK_MAX_LEN)
		return (EINVAL);

	if (pr == &prison0)
		pax_aslr_stack_len = val;

	pr->pr_hardening.hr_pax_aslr_stack_len = val;

	return (0);
}

static int
sysctl_pax_aslr_exec(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hardening.hr_pax_aslr_exec_len;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	if (val < PAX_ASLR_DELTA_EXEC_MIN_LEN ||
	    val > PAX_ASLR_DELTA_EXEC_MAX_LEN)
		return (EINVAL);

	if (pr == &prison0)
		pax_aslr_exec_len = val;

	pr->pr_hardening.hr_pax_aslr_exec_len = val;

	return (0);
}

/* COMPAT_FREEBSD32 and linuxulator. */
#ifdef COMPAT_FREEBSD32
static int sysctl_pax_aslr_compat_status(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_compat_mmap(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_compat_stack(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_compat_exec(SYSCTL_HANDLER_ARGS);

SYSCTL_NODE(_hardening_pax_aslr, OID_AUTO, compat, CTLFLAG_RD, 0,
    "Setting for COMPAT_FREEBSD32 and linuxulator.");

SYSCTL_PROC(_hardening_pax_aslr_compat, OID_AUTO, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_compat_status, "I",
    "Restrictions status. "
    "0 - disabled, "
    "1 - enabled,  "
    "2 - global enabled, "
    "3 - force global enabled");

SYSCTL_PROC(_hardening_pax_aslr_compat, OID_AUTO, mmap_len,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_compat_mmap, "I",
    "Number of bits randomized for mmap(2) calls. "
    "32 bit: [8,16]");

SYSCTL_PROC(_hardening_pax_aslr_compat, OID_AUTO, stack_len,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_compat_stack, "I",
    "Number of bits randomized for the stack. "
    "32 bit: [6,12]");

SYSCTL_PROC(_hardening_pax_aslr_compat, OID_AUTO, exec_len,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_compat_exec, "I",
    "Number of bits randomized for the PIE exec base. "
    "32 bit: [6,12]");

static int
sysctl_pax_aslr_compat_status(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hardening.hr_pax_aslr_compat_status;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	switch (val) {
	case PAX_FEATURE_DISABLED:
	case PAX_FEATURE_OPTIN:
	case PAX_FEATURE_OPTOUT:
	case PAX_FEATURE_FORCE_ENABLED:
		if (pr == &prison0)
			pax_aslr_compat_status = val;

		pr->pr_hardening.hr_pax_aslr_compat_status = val;
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

static int
sysctl_pax_aslr_compat_mmap(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hardening.hr_pax_aslr_compat_mmap_len;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || !req->newptr)
		return (err);

	if (val < PAX_ASLR_COMPAT_DELTA_MMAP_MIN_LEN ||
	    val > PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN)
		return (EINVAL);

	if (pr == &prison0)
		pax_aslr_compat_mmap_len = val;

	pr->pr_hardening.hr_pax_aslr_compat_mmap_len = val;

	return (0);
}

static int
sysctl_pax_aslr_compat_stack(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hardening.hr_pax_aslr_compat_stack_len;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || !req->newptr)
		return (err);

	if (val < PAX_ASLR_COMPAT_DELTA_STACK_MIN_LEN ||
	    val > PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN)
		return (EINVAL);

	if (pr == &prison0)
		pax_aslr_compat_stack_len = val;

	pr->pr_hardening.hr_pax_aslr_compat_stack_len = val;

	return (0);
}

static int
sysctl_pax_aslr_compat_exec(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hardening.hr_pax_aslr_compat_exec_len;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || !req->newptr)
		return (err);

	if (val < PAX_ASLR_COMPAT_DELTA_EXEC_MIN_LEN ||
	    val > PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN)
		return (EINVAL);

	if (pr == &prison0)
		pax_aslr_compat_exec_len = val;

	pr->pr_hardening.hr_pax_aslr_compat_exec_len = val;

	return (0);
}

#endif /* COMPAT_FREEBSD32 */
#endif /* PAX_SYSCTLS */


/*
 * ASLR functions
 */

static void
pax_aslr_sysinit(void)
{

	switch (pax_aslr_status) {
	case PAX_FEATURE_DISABLED:
	case PAX_FEATURE_OPTIN:
	case PAX_FEATURE_OPTOUT:
	case PAX_FEATURE_FORCE_ENABLED:
		break;
	default:
		printf("[PAX ASLR] WARNING, invalid PAX settings in loader.conf!"
		    " (pax_aslr_status = %d)\n", pax_aslr_status);
		pax_aslr_status = PAX_FEATURE_FORCE_ENABLED;
		break;
	}
	printf("[PAX ASLR] status: %s\n", pax_status_str[pax_aslr_status]);
	printf("[PAX ASLR] mmap: %d bit\n", pax_aslr_mmap_len);
	printf("[PAX ASLR] exec base: %d bit\n", pax_aslr_exec_len);
	printf("[PAX ASLR] stack: %d bit\n", pax_aslr_stack_len);
}
SYSINIT(pax_aslr, SI_SUB_PAX, SI_ORDER_SECOND, pax_aslr_sysinit, NULL);

int
pax_aslr_active(struct proc *p)
{
	uint32_t flags;

	pax_get_flags(p, &flags);

	CTR3(KTR_PAX, "%s: pid = %d p_pax = %x",
	    __func__, p->p_pid, flags);

	if ((flags & PAX_NOTE_ASLR) == PAX_NOTE_ASLR)
		return (true);

	if ((flags & PAX_NOTE_NOASLR) == PAX_NOTE_NOASLR)
		return (false);

	return (true);
}

void
pax_aslr_init_vmspace(struct proc *p)
{
	struct prison *pr;
	struct vmspace *vm;
	unsigned long rand_buf;

	vm = p->p_vmspace;
	KASSERT(vm != NULL, ("%s: vm is null", __func__));

	pr = pax_get_prison(p);
	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_mmap = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_DELTA_MMAP_LSB,
	    pr->pr_hardening.hr_pax_aslr_mmap_len);

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_stack = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_DELTA_STACK_LSB,
	    pr->pr_hardening.hr_pax_aslr_stack_len);
	vm->vm_aslr_delta_stack = ALIGN(vm->vm_aslr_delta_stack);

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_exec = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_DELTA_EXEC_LSB,
	    pr->pr_hardening.hr_pax_aslr_exec_len);

	CTR2(KTR_PAX, "%s: vm_aslr_delta_mmap=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_mmap);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_stack=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_stack);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_exec=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_exec);
}

#ifdef COMPAT_FREEBSD32
static void
pax_compat_aslr_sysinit(void)
{

	switch (pax_aslr_compat_status) {
	case PAX_FEATURE_DISABLED:
	case PAX_FEATURE_OPTIN:
	case PAX_FEATURE_OPTOUT:
	case PAX_FEATURE_FORCE_ENABLED:
		break;
	default:
		printf("[PAX ASLR (compat)] WARNING, invalid PAX settings in loader.conf! "
		    "(pax_aslr_compat_status = %d)\n", pax_aslr_compat_status);
		pax_aslr_compat_status = PAX_FEATURE_FORCE_ENABLED;
		break;
	}
	printf("[PAX ASLR (compat)] status: %s\n", pax_status_str[pax_aslr_compat_status]);
	printf("[PAX ASLR (compat)] mmap: %d bit\n", pax_aslr_compat_mmap_len);
	printf("[PAX ASLR (compat)] exec base: %d bit\n", pax_aslr_compat_exec_len);
	printf("[PAX ASLR (compat)] stack: %d bit\n", pax_aslr_compat_stack_len);
}
SYSINIT(pax_compat_aslr, SI_SUB_PAX, SI_ORDER_SECOND, pax_compat_aslr_sysinit, NULL);

void
pax_aslr_init_vmspace32(struct proc *p)
{
	struct prison *pr;
	struct vmspace *vm;
	long rand_buf;

	vm = p->p_vmspace;
	KASSERT(vm != NULL, ("%s: vm is null", __func__));

	pr = pax_get_prison(p);
	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_mmap = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_COMPAT_DELTA_MMAP_LSB,
	    pr->pr_hardening.hr_pax_aslr_compat_mmap_len);

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_stack = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_COMPAT_DELTA_STACK_LSB,
	    pr->pr_hardening.hr_pax_aslr_compat_stack_len);
	vm->vm_aslr_delta_stack = ALIGN(vm->vm_aslr_delta_stack);

	arc4rand(&rand_buf, sizeof(rand_buf), 0);
	vm->vm_aslr_delta_exec = PAX_ASLR_DELTA(rand_buf,
	    PAX_ASLR_COMPAT_DELTA_EXEC_LSB,
	    pr->pr_hardening.hr_pax_aslr_compat_exec_len);

	CTR2(KTR_PAX, "%s: vm_aslr_delta_mmap=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_mmap);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_stack=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_stack);
	CTR2(KTR_PAX, "%s: vm_aslr_delta_exec=%p\n",
	    __func__, (void *)vm->vm_aslr_delta_exec);
}
#endif

void
pax_aslr_init(struct image_params *imgp)
{
	struct proc *p;

	KASSERT(imgp != NULL, ("%s: imgp is null", __func__));
	p = imgp->proc;

	if (!pax_aslr_active(p))
		return;

	if (imgp->sysent->sv_pax_aslr_init != NULL)
		imgp->sysent->sv_pax_aslr_init(p);
}

void
pax_aslr_init_prison(struct prison *pr)
{
	struct prison *pr_p;

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	if (pr == &prison0) {
		/* prison0 has no parent, use globals */
		pr->pr_hardening.hr_pax_aslr_status = pax_aslr_status;
		pr->pr_hardening.hr_pax_aslr_mmap_len =
		    pax_aslr_mmap_len;
		pr->pr_hardening.hr_pax_aslr_stack_len =
		    pax_aslr_stack_len;
		pr->pr_hardening.hr_pax_aslr_exec_len =
		    pax_aslr_exec_len;
	} else {
		KASSERT(pr->pr_parent != NULL,
		   ("%s: pr->pr_parent == NULL", __func__));
		pr_p = pr->pr_parent;

		pr->pr_hardening.hr_pax_aslr_status =
		    pr_p->pr_hardening.hr_pax_aslr_status;
		pr->pr_hardening.hr_pax_aslr_mmap_len =
		    pr_p->pr_hardening.hr_pax_aslr_mmap_len;
		pr->pr_hardening.hr_pax_aslr_stack_len =
		    pr_p->pr_hardening.hr_pax_aslr_stack_len;
		pr->pr_hardening.hr_pax_aslr_exec_len =
		    pr_p->pr_hardening.hr_pax_aslr_exec_len;
	}
}

#ifdef COMPAT_FREEBSD32
void
pax_aslr_init_prison32(struct prison *pr)
{
	struct prison *pr_p;

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	if (pr == &prison0) {
		/* prison0 has no parent, use globals */

		pr->pr_hardening.hr_pax_aslr_compat_status =
		    pax_aslr_compat_status;
		pr->pr_hardening.hr_pax_aslr_compat_mmap_len =
		    pax_aslr_compat_mmap_len;
		pr->pr_hardening.hr_pax_aslr_compat_stack_len =
		    pax_aslr_compat_stack_len;
		pr->pr_hardening.hr_pax_aslr_compat_exec_len =
		    pax_aslr_compat_exec_len;
	} else {
		KASSERT(pr->pr_parent != NULL,
		   ("%s: pr->pr_parent == NULL", __func__));
		pr_p = pr->pr_parent;

		pr->pr_hardening.hr_pax_aslr_compat_status =
		    pr_p->pr_hardening.hr_pax_aslr_compat_status;
		pr->pr_hardening.hr_pax_aslr_compat_mmap_len =
		    pr_p->pr_hardening.hr_pax_aslr_compat_mmap_len;
		pr->pr_hardening.hr_pax_aslr_compat_stack_len =
		    pr_p->pr_hardening.hr_pax_aslr_compat_stack_len;
		pr->pr_hardening.hr_pax_aslr_compat_exec_len =
		    pr_p->pr_hardening.hr_pax_aslr_compat_exec_len;
	}
}
#endif /* COMPAT_FREEBSD32 */

void
pax_aslr_mmap(struct proc *p, vm_offset_t *addr, vm_offset_t orig_addr, int flags)
{

	if (!pax_aslr_active(p))
		return;

	if (!(flags & MAP_FIXED) && ((orig_addr == 0) || !(flags & MAP_ANON))) {
		CTR4(KTR_PAX, "%s: applying to %p orig_addr=%p flags=%x\n",
		    __func__, (void *)*addr, (void *)orig_addr, flags);

#ifdef MAP_32BIT
		if (flags & MAP_32BIT) {
			int len_32bit;

#ifdef COMPAT_FREEBSD32
			len_32bit = pax_aslr_compat_mmap_len;
#else
			len_32bit = PAX_ASLR_COMPAT_DELTA_MMAP_MIN_LEN;
#endif
			*addr += PAX_ASLR_DELTA(arc4random(),
			    PAX_ASLR_COMPAT_DELTA_MMAP_LSB,
			    len_32bit);
		 } else
#endif /* MAP_32BIT */
			*addr += p->p_vmspace->vm_aslr_delta_mmap;
		CTR2(KTR_PAX, "%s: result %p\n", __func__, (void *)*addr);
	} else
		CTR4(KTR_PAX, "%s: not applying to %p orig_addr=%p flags=%x\n",
		    __func__, (void *)*addr, (void *)orig_addr, flags);
}

void
pax_aslr_stack(struct proc *p, uintptr_t *addr)
{
	uintptr_t orig_addr;

	if (!pax_aslr_active(p))
		return;

	orig_addr = *addr;
	*addr -= p->p_vmspace->vm_aslr_delta_stack;
	CTR3(KTR_PAX, "%s: orig_addr=%p, new_addr=%p\n",
	    __func__, (void *)orig_addr, (void *)*addr);
}

void
pax_aslr_stack_adjust(struct proc *p, u_long *ssiz)
{
	struct rlimit rlim_stack;

	if (!pax_aslr_active(p))
		return;

	*ssiz += p->p_vmspace->vm_aslr_delta_stack;

	/*
	 * This needed because we currently use
	 * gap based stack randomization.
	 */
	PROC_LOCK(p);
	lim_rlimit(p, RLIMIT_STACK, &rlim_stack);
	PROC_UNLOCK(p);
	if (*ssiz > rlim_stack.rlim_max)
		rlim_stack.rlim_max = *ssiz;
	if (*ssiz > rlim_stack.rlim_cur)
		rlim_stack.rlim_cur = *ssiz;
	kern_setrlimit(curthread, RLIMIT_STACK, &rlim_stack);
}

void
pax_aslr_execbase(struct proc *p, u_long *et_dyn_addrp)
{

	if (!pax_aslr_active(p))
		return;

	*et_dyn_addrp += p->p_vmspace->vm_aslr_delta_exec;
}

uint32_t
pax_aslr_setup_flags(struct image_params *imgp, uint32_t mode)
{
	struct prison *pr;
	uint32_t flags, status;

	flags = 0;
	status = 0;

	pr = pax_get_prison(imgp->proc);
	status = pr->pr_hardening.hr_pax_aslr_status;

	if (status == PAX_FEATURE_DISABLED) {
		flags &= ~PAX_NOTE_ASLR;
		flags |= PAX_NOTE_NOASLR;

		return (flags);
	}

	if (status == PAX_FEATURE_FORCE_ENABLED) {
		flags |= PAX_NOTE_ASLR;
		flags &= ~PAX_NOTE_NOASLR;

		return (flags);
	}

	if (status == PAX_FEATURE_OPTIN) {
		if (mode & PAX_NOTE_ASLR) {
			flags |= PAX_NOTE_ASLR;
			flags &= ~PAX_NOTE_NOASLR;
		} else {
			flags &= ~PAX_NOTE_ASLR;
			flags |= PAX_NOTE_NOASLR;
		}

		return (flags);
	}

	if (status == PAX_FEATURE_OPTOUT) {
		if (mode & PAX_NOTE_NOASLR) {
			flags &= ~PAX_NOTE_ASLR;
			flags |= PAX_NOTE_NOASLR;
		} else {
			flags |= PAX_NOTE_ASLR;
			flags &= ~PAX_NOTE_NOASLR;
		}

		return (flags);
	}

	/*
	 * unknown status, force ASLR
	 */
	flags |= PAX_NOTE_ASLR;
	flags &= ~PAX_NOTE_NOASLR;

	return (flags);
}

