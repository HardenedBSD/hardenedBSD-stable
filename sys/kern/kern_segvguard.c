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

int pax_segvguard_status = 0;
int pax_segvguard_debug = 0;
int pax_segvguard_expiry = PAX_SEGVGUARD_EXPIRY;
int pax_segvguard_suspension = PAX_SEGVGUARD_SUSPENSION;
int pax_segvguard_maxcrashes = PAX_SEGVGUARD_MAXCRASHES;

struct pax_segvguard_uid_entry {
	uid_t sue_uid;
	size_t sue_ncrashes;
	time_t sue_expiry;
	time_t sue_suspended;
	LIST_ENTRY(pax_segvguard_uid_entry) sue_list;
};

struct pax_segvguard_vnodes {
	uint32_t sv_inode;
	char sv_mntpoint[MNAMELEN];
	LIST_ENTRY(pax_segvguard_vnodes) sv_list;
	LIST_HEAD(, pax_segvguard_uid_entry) uid_list;
};

static LIST_HEAD(, pax_segvguard_vnodes) vnode_list = LIST_HEAD_INITIALIZER(&vnode_list);
struct mtx segvguard_mtx;

static int sysctl_pax_segvguard_status(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_debug(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_expiry(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_suspension(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_maxcrashes(SYSCTL_HANDLER_ARGS);

static bool pax_segvguard_active(struct thread *td, struct proc *proc);

SYSCTL_NODE(_security_pax, OID_AUTO, segvguard, CTLFLAG_RD, 0, "PaX segvguard");

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_segvguard_status, "I",
    "Guard status. "
    "0 - disabled, "
    "1 - enabled,  "
    "2 - global enabled, "
    "3 - force global enabled");
TUNABLE_INT("security.pax.segvguard.status", &pax_segvguard_status);

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, debug,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_segvguard_debug, "I",
    "Debug mode.");
TUNABLE_INT("security.pax.segvguard.debug", &pax_segvguard_debug);

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, expiry_timeout,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_segvguard_expiry, "I",
    "Entry expiry timeout (in seconds).");
TUNABLE_INT("security.pax.segvguard.expiry_timeout", &pax_segvguard_expiry);

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, suspend_timeout,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_segvguard_suspension, "I",
    "Entry suspension timeout (int seconds).");
TUNABLE_INT("security.pax.segvguard.suspend_timeout", &pax_segvguard_suspension);

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, max_crashes,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_segvguard_maxcrashes, "I",
    "Max number of crashes before expiry.");
TUNABLE_INT("security.pax.segvguard.max_crashes", &pax_segvguard_maxcrashes);

static int
sysctl_pax_segvguard_status(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;
	struct prison *pr=NULL;

	pr = pax_get_prison(req->td, NULL);

	if ((pr != NULL) && !(pr->pr_pax_set))
		pax_init_prison(pr);

	val = (pr != NULL) ? pr->pr_pax_segvguard_status : pax_segvguard_status;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	switch (val) {
	case    PAX_SEGVGUARD_DISABLED:
	case    PAX_SEGVGUARD_ENABLED:
	case    PAX_SEGVGUARD_GLOBAL_ENABLED:
	case    PAX_SEGVGUARD_FORCE_GLOBAL_ENABLED:
		if ((pr == NULL) || (pr == &prison0))
			pax_segvguard_status = val;
		if (pr != NULL)
			pr->pr_pax_segvguard_status = val;
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

static int
sysctl_pax_segvguard_expiry(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;
	struct prison *pr=NULL;

	pr = pax_get_prison(req->td, NULL);

	if ((pr != NULL) && !(pr->pr_pax_set))
		pax_init_prison(pr);

	val = (pr != NULL) ? pr->pr_pax_segvguard_expiry : pax_segvguard_expiry;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	if ((pr == NULL) || (pr == &prison0))
		pax_segvguard_expiry = val;
	if (pr != NULL)
		pr->pr_pax_segvguard_expiry = val;

	return (0);
}

static int
sysctl_pax_segvguard_suspension(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;
	struct prison *pr=NULL;

	pr = pax_get_prison(req->td, NULL);

	if ((pr != NULL) && !(pr->pr_pax_set))
		pax_init_prison(pr);

	val = (pr != NULL) ? pr->pr_pax_segvguard_suspension : pax_segvguard_suspension;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	if ((pr == NULL) || (pr == &prison0))
		pax_segvguard_suspension = val;
	if (pr != NULL)
		pr->pr_pax_segvguard_suspension = val;

	return (0);
}

static int
sysctl_pax_segvguard_maxcrashes(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;
	struct prison *pr=NULL;

	pr = pax_get_prison(req->td, NULL);

	if ((pr != NULL) && !(pr->pr_pax_set))
		pax_init_prison(pr);

	val = (pr != NULL) ? pr->pr_pax_segvguard_maxcrashes : pax_segvguard_maxcrashes;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	if ((pr == NULL) || (pr == &prison0))
		pax_segvguard_maxcrashes = val;
	if (pr != NULL)
		pr->pr_pax_segvguard_maxcrashes = val;

	return (0);
}

static int
sysctl_pax_segvguard_debug(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;
	struct prison *pr=NULL;

	pr = pax_get_prison(req->td, NULL);

	if ((pr != NULL) && !(pr->pr_pax_set))
		pax_init_prison(pr);

	val = (pr != NULL) ? pr->pr_pax_segvguard_debug : pax_segvguard_debug;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	if ((pr == NULL) || (pr == &prison0))
		pax_segvguard_debug = val;
	if (pr != NULL)
		pr->pr_pax_segvguard_debug = val;

	return (0);
}

MALLOC_DECLARE(M_PAX);
MALLOC_DEFINE(M_PAX, "pax_segvguard", "PaX segvguard memory");

bool
pax_segvguard_active(struct thread *td, struct proc *proc)
{
	int status;
	struct prison *pr=NULL;
	uint32_t flags;
    bool haspax;

	if ((td == NULL) && (proc == NULL))
		return (true);

	flags = (td != NULL) ? td->td_proc->p_pax : proc->p_pax;
	pr = pax_get_prison(td, proc);

	if ((pr != NULL) && !(pr->pr_pax_set))
		pax_init_prison(pr);

	status = (pr != NULL) ? pr->pr_pax_segvguard_status : pax_segvguard_status;

    if (td != NULL) {
        if (td->td_proc->p_haspax)
            haspax = 1;
    } else {
        if (proc->p_haspax)
            haspax = 1;
    }

	switch (status) {
	case    PAX_SEGVGUARD_DISABLED:
		return (false);
	case    PAX_SEGVGUARD_FORCE_GLOBAL_ENABLED:
		return (true);
	case    PAX_SEGVGUARD_ENABLED:
		if (haspax && (flags & ELF_NOTE_PAX_GUARD) == 0)
			return (false);
		break;
	case    PAX_SEGVGUARD_GLOBAL_ENABLED:
		if (haspax && (flags & ELF_NOTE_PAX_NOGUARD) != 0)
			return (false);
		break;
	default:
		return (true);
	}

	return (true);
}

static void
pax_segvguard_gc(void *args)
{
	struct pax_segvguard_vnodes *vn, *vn_saved;
	struct pax_segvguard_uid_entry *up, *up_saved;
	struct timeval tv;

	up = NULL;
	for (;;) {
		microtime(&tv);
		mtx_lock(&segvguard_mtx);

		vn = LIST_FIRST(&vnode_list);
		if (vn != NULL)
			up = LIST_FIRST(&vn->uid_list);

		up_saved = NULL;
		vn_saved = NULL;

		while (vn != NULL) {
			while (up != NULL) {
				if (up->sue_expiry < tv.tv_sec && !(up->sue_suspended)) {
					up_saved = up;
					LIST_REMOVE(up, sue_list);
				}
				up = LIST_NEXT(up, sue_list);
				if (up_saved != NULL)
					free(up_saved, M_PAX);
			}

			vn = LIST_NEXT(vn, sv_list);
		}

#if 0
		if (!LIST_EMPTY(&vnode_list)) {
			LIST_FOREACH(vn, &vnode_list, sv_list) {
				LIST_FOREACH(up, &vn->uid_list, sue_list) {
					if (up->sue_expiry < tv.tv_sec && !up->sue_suspended) {
						LIST_REMOVE(up, sue_list);
						free(up, M_PAX);
						continue;

#if 0
						if (LIST_EMPTY(&vn->uid_list)) {
							LIST_REMOVE(vn, sv_list);
							free(vn, M_PAX);
						}
#endif
					}
				}
			}
		}
#endif

		mtx_unlock(&segvguard_mtx);
		pause("-", 1000);
	}
}

static struct pax_segvguard_vnodes *
pax_segvguard_add_file(struct vnode *vn, struct stat *sb)
{
	struct pax_segvguard_vnodes *v;

	v = malloc(sizeof(struct pax_segvguard_vnodes), M_PAX, M_WAITOK);
	LIST_INIT(&(v->uid_list));

	v->sv_inode = sb->st_ino;
	strncpy(v->sv_mntpoint, vn->v_mount->mnt_stat.f_mntonname, MNAMELEN);
	v->sv_mntpoint[MNAMELEN-1] = '\0';

	LIST_INSERT_HEAD(&vnode_list, v, sv_list);

	return v;
}

static void
pax_segvguard_add_uid(struct thread *td, struct pax_segvguard_vnodes *vn, struct timeval *tv)
{
	struct pax_segvguard_uid_entry *up;
	struct prison *pr;

	pr = pax_get_prison(td, NULL);

	up = malloc(sizeof(struct pax_segvguard_uid_entry), M_PAX, M_WAITOK);
	up->sue_uid = td->td_ucred->cr_uid;
	up->sue_ncrashes = 1;
	up->sue_expiry = tv->tv_sec + ((pr != NULL) ? pr->pr_pax_segvguard_expiry : pax_segvguard_expiry);
	up->sue_suspended = 0;

	LIST_INSERT_HEAD(&(vn->uid_list), up, sue_list);
}

int segvguard_gc_init = 0;

int
pax_segvguard(struct thread *td, struct vnode *v, char *name, bool crashed)
{
	struct pax_segvguard_uid_entry *up;
	struct pax_segvguard_vnodes *vn, *vn_saved;
	struct timeval tv;
	struct stat sb;
	char *mntpoint;
	struct vnode *vp;
	bool vnode_found, uid_found;
	struct prison *pr;

	pr = pax_get_prison(td, NULL);

	if (!segvguard_gc_init) {
		struct proc *p;
		mtx_init(&segvguard_mtx, "segvguard mutex", NULL, MTX_DEF);
		kproc_create(pax_segvguard_gc, "PAX", &p, 0, 0, "segvguard_gc");
		segvguard_gc_init = 1;
	}

	if (!pax_segvguard_active(td, NULL))
		return (0);

	if (v == NULL)
		return (EFAULT);

	vp = v;
	vn_stat(vp, &sb, td->td_ucred, NOCRED, curthread);
	mntpoint = vp->v_mount->mnt_stat.f_mntonname;

	mtx_lock(&segvguard_mtx);

	if (LIST_EMPTY(&vnode_list) && !crashed) {
		mtx_unlock(&segvguard_mtx);
		return (0);
	}

	microtime(&tv);

	if (!LIST_EMPTY(&vnode_list) && !crashed) {
		LIST_FOREACH(vn, &vnode_list, sv_list) {
			if (vn->sv_inode == sb.st_ino &&
			    !strncmp(mntpoint, vn->sv_mntpoint, MNAMELEN)) {
				LIST_FOREACH(up, &(vn->uid_list), sue_list) {
					if (td->td_ucred->cr_uid == up->sue_uid) {
						mtx_unlock(&segvguard_mtx);
						return (EPERM);
					}
				}
			}
		}
	}

	/*
	 * If a program we don't know about crashed, we need to create a new entry for it
	 */
	if (LIST_EMPTY(&vnode_list) && crashed) {
		vn = pax_segvguard_add_file(vp, &sb);
		pax_segvguard_add_uid(td, vn, &tv);
		mtx_unlock(&segvguard_mtx);
		return (0);
	}

	vnode_found = uid_found = 0;
	if (!LIST_EMPTY(&vnode_list) && crashed) {
		LIST_FOREACH(vn, &vnode_list, sv_list) {
			if (vn->sv_inode == sb.st_ino && !strncmp(mntpoint, vn->sv_mntpoint, MNAMELEN)) {
				vnode_found = 1;
				vn_saved = vn;
				LIST_FOREACH(up, &(vn->uid_list), sue_list) {
					if (td->td_ucred->cr_uid == up->sue_uid) {
						if (up->sue_expiry < tv.tv_sec && up->sue_suspended <= tv.tv_sec) {
							up->sue_ncrashes = 1;
							up->sue_expiry = tv.tv_sec + ((pr != NULL) ? pr->pr_pax_segvguard_expiry : pax_segvguard_expiry);
							up->sue_suspended = 0;

							mtx_unlock(&segvguard_mtx);
							return (0);
						}

						uid_found = 1;
						up->sue_ncrashes++;
						if (up->sue_ncrashes >= pax_segvguard_maxcrashes) {
							up->sue_suspended = tv.tv_sec + ((pr != NULL) ? pr->pr_pax_segvguard_suspension : pax_segvguard_suspension);
							up->sue_ncrashes = 0;
							up->sue_expiry = 0;
						}

						mtx_unlock(&segvguard_mtx);
						return (0);
					}
				}
			}
		}
	}

	if (crashed) {
		if (!vnode_found) {
			vn = pax_segvguard_add_file(vp, &sb);
			pax_segvguard_add_uid(td, vn, &tv);
		} else if (!uid_found) {
			pax_segvguard_add_uid(td, vn_saved, &tv);
		}
	}

	mtx_unlock(&segvguard_mtx);

	return (0);
}
