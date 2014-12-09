/*-
 * Copyright (c) 2006 Elad Efrat <elad@NetBSD.org>
 * Copyright (c) 2013-2014, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
 * Copyright (c) 2014, by Shawn Webb <lattera at gmail.com>
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
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysent.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/elf_common.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/libkern.h>
#include <sys/jail.h>

#include <sys/mman.h>
#include <sys/libkern.h>
#include <sys/exec.h>
#include <sys/kthread.h>

#include <sys/syslimits.h>
#include <sys/param.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>

#include <machine/elf.h>

#include <sys/pax.h>

SYSCTL_NODE(_hardening, OID_AUTO, pax, CTLFLAG_RD, 0,
    "PaX (exploit mitigation) features.");

static int HardenedBSD_version = __HardenedBSD_version;
SYSCTL_INT(_hardening, OID_AUTO, version, CTLFLAG_RD|CTLFLAG_CAPRD,
    &HardenedBSD_version, 0, "HardenedBSD version");

const char *pax_status_str[] = {
	[PAX_FEATURE_DISABLED] = "disabled",
	[PAX_FEATURE_OPTIN] = "opt-in",
	[PAX_FEATURE_OPTOUT] = "opt-out",
	[PAX_FEATURE_FORCE_ENABLED] = "force enabled",
	[PAX_FEATURE_UNKNOWN_STATUS] = "UNKNOWN -> changed to \"force enabled\""
};

const char *pax_status_simple_str[] = {
	[PAX_FEATURE_SIMPLE_DISABLED] = "disabled",
	[PAX_FEATURE_SIMPLE_ENABLED] = "enabled"
};

struct prison *
pax_get_prison(struct proc *p)
{

	/* p can be NULL with kernel threads, so use prison0 */
	if (p == NULL || p->p_ucred == NULL)
		return (&prison0);

	return (p->p_ucred->cr_prison);
}

void
pax_get_flags(struct proc *p, uint32_t *flags)
{

	*flags = p->p_pax;
}

int
pax_elf(struct image_params *imgp, uint32_t mode)
{
	u_int flags, flags_aslr, flags_segvuard, flags_hardening;

	flags = mode;
	flags_aslr = flags_segvuard = flags_hardening = 0;

	if ((flags & ~PAX_NOTE_ALL) != 0) {
		pax_log_aslr(imgp->proc, __func__, "unknown paxflags: %x\n", flags);
		pax_ulog_aslr(NULL, "unknown paxflags: %x\n", flags);

		return (ENOEXEC);
	}

	if (((mode & PAX_NOTE_ALL_ENABLED) & ((mode & PAX_NOTE_ALL_DISABLED) >> 1)) != 0) {
		/*
		 * indicate flags inconsistencies in dmesg and in user terminal
		 */
		pax_log_aslr(imgp->proc, __func__, "inconsistent paxflags: %x\n", flags);
		pax_ulog_aslr(NULL, "inconsistent paxflags: %x\n", flags);

		return (ENOEXEC);
	}

#ifdef PAX_ASLR
	flags_aslr = pax_aslr_setup_flags(imgp, mode);
#endif

#ifdef PAX_SEGVGUARD
	flags_segvuard = pax_segvguard_setup_flags(imgp, mode);
#endif

#ifdef PAX_HARDENING_noyet
	flags_segvuard = pax_hardening_setup_flags(imgp, mode);
#endif

	flags = flags_aslr | flags_segvuard | flags_hardening;

	CTR3(KTR_PAX, "%s : flags = %x mode = %x",
	    __func__, flags, mode);

	imgp->pax_flags = flags;
	imgp->proc->p_pax = flags;

	return (0);
}


/*
 * print out PaX settings on boot time, and validate some of them
 */
static void
pax_sysinit(void)
{

	printf("PAX: initialize and check PaX and HardeneBSD features.\n");
}
SYSINIT(pax, SI_SUB_PAX, SI_ORDER_FIRST, pax_sysinit, NULL);

void
pax_init_prison(struct prison *pr)
{

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	pax_aslr_init_prison(pr);
	pax_hardening_init_prison(pr);
	pax_segvguard_init_prison(pr);
	pax_ptrace_hardening_init_prison(pr);

#ifdef COMPAT_FREEBSD32
	pax_aslr_init_prison32(pr);
#endif
}
