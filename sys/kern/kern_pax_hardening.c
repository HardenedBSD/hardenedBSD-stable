/*-
 * Copyright (c) 2006 Elad Efrat <elad@NetBSD.org>
 * Copyright (c) 2013-2014, by Oliver Pinter <oliver.pntr at gmail.com>
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

#include <security/mac_bsdextended/mac_bsdextended.h>

#ifdef PAX_HARDENING
int pax_map32_enabled_global = PAX_FEATURE_SIMPLE_DISABLED;
#else
int pax_map32_enabled_global = PAX_FEATURE_SIMPLE_ENABLED;
#endif

static int sysctl_pax_allow_map32(SYSCTL_HANDLER_ARGS);

#ifdef PAX_SYSCTLS
SYSCTL_PROC(_hardening, OID_AUTO, allow_map32bit,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_allow_map32, "I",
    "mmap MAP_32BIT support. "
    "0 - disabled, "
    "1 - enabled.");
#endif

TUNABLE_INT("hardening.allow_map32bit", &pax_map32_enabled_global);

static void
pax_hardening_sysinit(void)
{
	switch (pax_map32_enabled_global) {
	case PAX_FEATURE_SIMPLE_DISABLED:
	case PAX_FEATURE_SIMPLE_ENABLED:
		break;
	default:
		printf("[PAX HARDENING] WARNING, invalid settings in loader.conf!"
		    " (pax_map32_enabled_global = %d)\n", pax_map32_enabled_global);
		pax_map32_enabled_global = PAX_FEATURE_SIMPLE_DISABLED;
	}
	printf("[PAX HARDENING] mmap MAP32_bit support: %s\n",
	    pax_status_simple_str[pax_map32_enabled_global]);
}
SYSINIT(pax_hardening, SI_SUB_PAX, SI_ORDER_SECOND, pax_hardening_sysinit, NULL);

#ifdef PAX_SYSCTLS
static int
sysctl_pax_allow_map32(SYSCTL_HANDLER_ARGS)
{
	struct prison *pr;
	int err, val;

	pr = pax_get_prison(req->td->td_proc);

	val = (pr != NULL) ? pr->pr_pax_map32_enabled : pax_map32_enabled_global;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	if (val > 1 || val < -1)
		return (EINVAL);

	if ((pr == NULL) || (pr == &prison0))
		pax_map32_enabled_global = val;

	if (pr != NULL) {
		prison_lock(pr);
		pr->pr_pax_map32_enabled = val;
		prison_unlock(pr);
	}

	return (0);
}
#endif

int
pax_map32_enabled(struct thread *td)
{
	struct prison *pr;

	pr = pax_get_prison(td->td_proc);

	if (pr != NULL && pr != &prison0)
		return (pr->pr_pax_map32_enabled);

	return (pax_map32_enabled_global);
}
