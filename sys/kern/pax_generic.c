
/*-
 * Copyright (c) 2013, by Oliver Pinter <oliver.pntr at gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the developer may NOT be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 *
 * Enhancements made by Shawn "lattera" Webb under the direction of SoldierX.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"
#include "opt_pax.h"

#define _PAX_INTERNAL 1

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
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

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>

#include <machine/elf.h>

#include <sys/pax.h>

#ifdef PAX_ASLR
extern int pax_aslr_mmap_len;
extern int pax_aslr_stack_len;
extern int pax_aslr_exec_len;
#ifdef COMPAT_FREEBSD32
extern int pax_aslr_compat_mmap_len;
extern int pax_aslr_compat_stack_len;
extern int pax_aslr_compat_exec_len;
#endif
#endif /* PAX_ASLR */

#ifdef PAX_SEGVGUARD
extern int pax_segvguard_status;
extern int pax_segvguard_debug;
extern int pax_segvguard_expiry;
extern int pax_segvguard_suspension;
extern int pax_segvguard_maxcrashes;
#endif /* PAX_SEGVGUARD */

struct prison *
pax_get_prison(struct thread *td, struct proc *proc)
{
	if (td != NULL) {
		if ((td->td_proc) && (td->td_proc->p_ucred))
			return td->td_proc->p_ucred->cr_prison;

		return NULL;
	}

	if (proc == NULL)
		return NULL;

	return proc->p_ucred->cr_prison;
}

void
pax_elf(struct image_params *imgp)
{
	int idx;
	struct note_pax *notes;
	const Elf_Shdr *shdr;
	const Elf_Ehdr *hdr;
	struct prison *pr;

	pr = pax_get_prison(NULL, imgp->proc);
	if (pr != NULL) {
		if (!(pr->pr_pax_aslr_status))
			return;
	} else {
		if (!pax_aslr_status)
			return;
	}

	hdr = (Elf_Ehdr *)(imgp->image_header);
	shdr = (Elf_Shdr *)(imgp->image_header + hdr->e_shoff);
	for (idx = 0; idx < hdr->e_shnum; idx++) {
		if (shdr[idx].sh_type == SHT_NOTE && shdr[idx].sh_size == 20) {
			notes = (struct note_pax *)(imgp->image_header + shdr[idx].sh_offset);
			if (notes->pax_tag == ELF_NOTE_TYPE_PAX_TAG) {
				imgp->pax_flags = notes->flags;
				PROC_LOCK(imgp->proc);
				imgp->proc->p_pax = notes->flags;
				PROC_UNLOCK(imgp->proc);
			}
		}
	}
}

void
pax_init_prison(struct prison *pr)
{
	if (pr == NULL)
		return;

	if (pr->pr_pax_set)
		return;

	if (pax_aslr_debug)
		uprintf("[PaX ASLR/SEGVGUARD] %s: Setting prison %s ASLR variables\n",
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
#endif
#endif

#ifdef PAX_SEGVGUARD
	pr->pr_pax_segvguard_status = pax_segvguard_status;
	pr->pr_pax_segvguard_debug = pax_segvguard_debug;
	pr->pr_pax_segvguard_expiry = pax_segvguard_expiry;
	pr->pr_pax_segvguard_suspension = pax_segvguard_suspension;
	pr->pr_pax_segvguard_maxcrashes = pax_segvguard_maxcrashes;
#endif

	pr->pr_pax_set = 1;
}
