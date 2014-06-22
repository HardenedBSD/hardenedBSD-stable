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

SYSCTL_NODE(_security, OID_AUTO, pax, CTLFLAG_RD, 0,
    "PaX (exploit mitigation) features.");

struct prison *
pax_get_prison(struct thread *td, struct proc *proc)
{

	if (td != NULL) {
		if ((td->td_proc != NULL) && (td->td_proc->p_ucred != NULL))
			return (td->td_proc->p_ucred->cr_prison);

		return (NULL);
	}
	if ((proc == NULL) || (proc->p_ucred == NULL))
		return (NULL);

	return (proc->p_ucred->cr_prison);
}

void
pax_elf(struct image_params *imgp, uint32_t mode)
{
	u_int flags = 0;

	if ((mode & MBI_ALLPAX) == MBI_ALLPAX)
		goto end;

	if (mode & MBI_FORCE_ASLR_ENABLED)
		flags |= PAX_NOTE_ASLR;
	else if (mode & MBI_FORCE_ASLR_DISABLED)
		flags |= PAX_NOTE_NOASLR;

end:
	if (imgp != NULL) {
		imgp->pax_flags = flags;
		if (imgp->proc != NULL) {
			PROC_LOCK(imgp->proc);
			imgp->proc->p_pax = flags;
			PROC_UNLOCK(imgp->proc);
		}
	}
}


/*
 * print out PaX settings on boot time, and validate some of them
 */
void
pax_init(void)
{
#if defined(PAX_ASLR)
	const char *status_str[] = {
		[0] = "disabled",
		[1] = "opt-in",
		[2] = "opt-out",
		[3] = "force enabled",
		[4] = "UNKNOWN -> changed to \"force enabled\""
	};
#endif

#ifdef PAX_ASLR
	switch (pax_aslr_status) {
	case	0:
	case	1:
	case	2:
	case	3:
		break;
	default:
		printf("[PAX ASLR] WARNING, invalid PAX settings in loader.conf!"
		    " (pax_aslr_status = %d)\n", pax_aslr_status);
		pax_aslr_status = 3;
		break;
	}
	printf("[PAX ASLR] status: %s\n", status_str[pax_aslr_status]);
	printf("[PAX ASLR] mmap: %d bit\n", pax_aslr_mmap_len);
	printf("[PAX ASLR] exec base: %d bit\n", pax_aslr_exec_len);
	printf("[PAX ASLR] stack: %d bit\n", pax_aslr_stack_len);

#ifdef COMPAT_FREEBSD32
	switch (pax_aslr_compat_status) {
	case	0:
	case	1:
	case	2:
	case	3:
		break;
	default:
		printf("[PAX ASLR (compat)] WARNING, invalid PAX settings in loader.conf! "
		    "(pax_aslr_compat_status = %d)\n", pax_aslr_compat_status);
		pax_aslr_compat_status = 3;
		break;
	}
	printf("[PAX ASLR (compat)] status: %s\n", status_str[pax_aslr_compat_status]);
	printf("[PAX ASLR (compat)] mmap: %d bit\n", pax_aslr_compat_mmap_len);
	printf("[PAX ASLR (compat)] exec base: %d bit\n", pax_aslr_compat_exec_len);
	printf("[PAX ASLR (compat)] stack: %d bit\n", pax_aslr_compat_stack_len);
#endif /* COMPAT_FREEBSD32 */
#endif /* PAX_ASLR */

	printf("[PAX LOG] logging to system: %d\n", pax_log_log);
	printf("[PAX LOG] logging to user: %d\n", pax_log_ulog);
}
SYSINIT(pax, SI_SUB_PAX, SI_ORDER_FIRST, pax_init, NULL);

void
pax_init_prison(struct prison *pr)
{

	if (pr == NULL)
		return;

	if (pr->pr_pax_set)
		return;

	mtx_lock(&(pr->pr_mtx));

	if (pax_aslr_debug)
		uprintf("[PaX ASLR] %s: Setting prison %s ASLR variables\n",
		    __func__, pr->pr_name);

#ifdef PAX_ASLR
	pr->pr_pax_aslr_status = pax_aslr_status;
	pr->pr_pax_aslr_debug = pax_aslr_debug;
	pr->pr_pax_aslr_mmap_len = pax_aslr_mmap_len;
	pr->pr_pax_aslr_stack_len = pax_aslr_stack_len;
	pr->pr_pax_aslr_exec_len = pax_aslr_exec_len;

#ifdef COMPAT_FREEBSD32
	pr->pr_pax_aslr_compat_status = pax_aslr_compat_status;
	pr->pr_pax_aslr_compat_mmap_len = pax_aslr_compat_mmap_len;
	pr->pr_pax_aslr_compat_stack_len = pax_aslr_compat_stack_len;
	pr->pr_pax_aslr_compat_exec_len = pax_aslr_compat_exec_len;
#endif /* COMPAT_FREEBSD32 */
#endif /* PAX_ASLR */

	pr->pr_pax_log_log = pax_log_log;
	pr->pr_pax_log_ulog = pax_log_ulog;

	pr->pr_pax_set = 1;

	mtx_unlock(&(pr->pr_mtx));
}
