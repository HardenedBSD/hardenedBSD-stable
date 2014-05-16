/*-
 * Copyright (c) 2013-2014, by Oliver Pinter <oliver.pntr at gmail.com>
 * Copyright (c) 2014, by Shawn Webb <lattera at gmail.com>
 * Copyright (c) 2014, Danilo Egea Gondolfo <danilogondolfo at gmail.com>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"
#include "opt_pax.h"

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
#include <sys/fnv_hash.h>

#include <sys/mman.h>
#include <sys/libkern.h>
#include <sys/exec.h>
#include <sys/kthread.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>

#include <machine/elf.h>

#include <sys/pax.h>

int pax_segvguard_status = PAX_SEGVGUARD_OPTIN;
int pax_segvguard_debug = 0;
int pax_segvguard_expiry = PAX_SEGVGUARD_EXPIRY;
int pax_segvguard_suspension = PAX_SEGVGUARD_SUSPENSION;
int pax_segvguard_maxcrashes = PAX_SEGVGUARD_MAXCRASHES;


struct pax_segvguard_entry {
	uid_t se_uid;
	ino_t se_inode;
	char se_mntpoint[MNAMELEN];

	size_t se_ncrashes;
	sbintime_t se_expiry;
	sbintime_t se_suspended;
	LIST_ENTRY(pax_segvguard_entry) se_entry;
};

static struct pax_segvguard_key {
	uid_t se_uid;
	ino_t se_inode;
	char se_mntpoint[MNAMELEN];
} *key;

LIST_HEAD(pax_segvguard_entryhead, pax_segvguard_entry);

static struct pax_segvguard_entryhead *pax_segvguard_hashtbl;
static u_long pax_segvguard_hashmask;
static int pax_segvguard_hashsize = 512;

#define PAX_SEGVGUARD_HASHVAL(x) \
	fnv_32_buf((&(x)), sizeof(x), FNV1_32_INIT)

#define PAX_SEGVGUARD_HASH(x) \
	(&pax_segvguard_hashtbl[PAX_SEGVGUARD_HASHVAL(x) & pax_segvguard_hashmask])

#define PAX_SEGVGUARD_KEY(x) \
	((struct pax_segvguard_key *) x)

MALLOC_DECLARE(M_PAX);
MALLOC_DEFINE(M_PAX, "pax_segvguard", "PaX segvguard memory");

struct mtx segvguard_mtx;

static int sysctl_pax_segvguard_status(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_debug(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_expiry(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_suspension(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_maxcrashes(SYSCTL_HANDLER_ARGS);

SYSCTL_DECL(_security_pax);

SYSCTL_NODE(_security_pax, OID_AUTO, segvguard, CTLFLAG_RD, 0, "PaX segvguard");

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_segvguard_status, "I",
    "Guard status. "
    "0 - disabled, "
    "1 - opt-in,  "
    "2 - opt-out, "
    "3 - force enabled");
TUNABLE_INT("security.pax.segvguard.status", &pax_segvguard_status);

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, debug,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_segvguard_debug, "I",
    "Debug mode.");
TUNABLE_INT("security.pax.segvguard.debug", &pax_segvguard_debug);

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, expiry_timeout,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_segvguard_expiry, "I",
    "Entry expiry timeout (in seconds).");
TUNABLE_INT("security.pax.segvguard.expiry_timeout", &pax_segvguard_expiry);

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, suspend_timeout,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_segvguard_suspension, "I",
    "Entry suspension timeout (in seconds).");
TUNABLE_INT("security.pax.segvguard.suspend_timeout", &pax_segvguard_suspension);

SYSCTL_PROC(_security_pax_segvguard, OID_AUTO, max_crashes,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
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
	case    PAX_SEGVGUARD_OPTIN:
	case    PAX_SEGVGUARD_OPTOUT:
	case    PAX_SEGVGUARD_FORCE_ENABLED:
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


static bool
pax_segvguard_active(struct thread *td, struct vnode *vn, struct proc *proc)
{
	int status;
	struct prison *pr=NULL;
	struct vattr vap;
	uint32_t flags;

	if ((td == NULL) && (proc == NULL))
		return (true);

	flags = (td != NULL) ? td->td_proc->p_pax : proc->p_pax;
	if (((flags & 0xaaaaaaaa) & ((flags & 0x55555555) << 1)) != 0) {
		uprintf("PAX: inconsistent paxflags: %x\n", flags);
		return (true);
	}

	pr = pax_get_prison(td, proc);
	if ((pr != NULL) && !(pr->pr_pax_set))
		pax_init_prison(pr);

	status = (pr != NULL) ? pr->pr_pax_segvguard_status : pax_segvguard_status;

	VOP_GETATTR(vn, &vap, td->td_ucred);

	switch (status) {
	case    PAX_SEGVGUARD_DISABLED:
		return (false);
	case    PAX_SEGVGUARD_FORCE_ENABLED:
		return (true);
	case    PAX_SEGVGUARD_OPTIN:
		/* TODO: The ugidfw flags isn't working */
		if ((vap.va_mode & (S_ISUID | S_ISGID)) == 0)
			return (false);
		break;
	case    PAX_SEGVGUARD_OPTOUT:
		if (flags && (flags & PAX_NOTE_NOGUARD) != 0)
			return (false);
		break;
	default:
		return (true);
	}

	return (true);
}

static struct pax_segvguard_entry *
pax_segvguard_add(struct thread *td, struct stat *sb, struct vnode *vn, sbintime_t sbt)
{
	struct pax_segvguard_entry *v;
	struct prison *pr;

	pr = pax_get_prison(td, NULL);

	v = malloc(sizeof(struct pax_segvguard_entry), M_PAX, M_NOWAIT);
	if (!v)
		return (NULL);

	v->se_inode = sb->st_ino;
	strncpy(v->se_mntpoint, vn->v_mount->mnt_stat.f_mntonname, MNAMELEN);

	v->se_uid = td->td_ucred->cr_uid;
	v->se_ncrashes = 1;
	v->se_expiry = sbt + ((pr != NULL) ? pr->pr_pax_segvguard_expiry : pax_segvguard_expiry) * SBT_1S;
	v->se_suspended = 0;

	key = PAX_SEGVGUARD_KEY(v);
	LIST_INSERT_HEAD(PAX_SEGVGUARD_HASH(*key), v, se_entry);

	return (v);
}

static struct pax_segvguard_entry *
pax_segvguard_lookup(struct thread *td, struct stat *sb, struct vnode *vn)
{
	struct pax_segvguard_entry *v;
	struct pax_segvguard_key sk;
	struct prison *pr;

	pr = pax_get_prison(td, NULL);

	sk.se_inode = sb->st_ino;
	strncpy(sk.se_mntpoint, vn->v_mount->mnt_stat.f_mntonname, MNAMELEN);
	sk.se_uid = td->td_ucred->cr_uid;

	LIST_FOREACH(v, PAX_SEGVGUARD_HASH(sk), se_entry) {
		if (v->se_inode == sb->st_ino &&
		    !strncmp(sk.se_mntpoint, v->se_mntpoint, MNAMELEN) &&
		    td->td_ucred->cr_uid == v->se_uid) {

			return (v);
		}
	}

	return (NULL);
}

int
pax_segvguard(struct thread *td, struct vnode *v, char *name, bool crashed)
{
	struct pax_segvguard_entry *se;
	struct prison *pr;
	struct stat sb;
	sbintime_t sbt;

	if (v == NULL)
		return (EFAULT);

	pr = pax_get_prison(td, NULL);

	vn_stat(v, &sb, td->td_ucred, NOCRED, curthread);

	if (pax_segvguard_active(td, v, NULL) == false)
		return (0);

	sbt = sbinuptime();

	mtx_lock(&segvguard_mtx);

	se = pax_segvguard_lookup(td, &sb, v);

	if (!crashed && se == NULL) {

		mtx_unlock(&segvguard_mtx);
		return (0);
	}

	if (!crashed && se != NULL) {
		if (se->se_suspended > sbt) {
			printf("PaX Segvguard: [%s (%d)] Preventing "
					"execution due to repeated segfaults.\n", name, td->td_proc->p_pid);

			mtx_unlock(&segvguard_mtx);
			return (EPERM);
		}
	}

	/*
	 * If a program we don't know about crashed, we need to create a new entry for it
	 */
	if (crashed && se == NULL) {
		pax_segvguard_add(td, &sb, v, sbt);

		mtx_unlock(&segvguard_mtx);
		return (0);
	}

	if (crashed && se != NULL) {
		if (se->se_expiry < sbt && se->se_suspended <= sbt) {
			printf("PaX Segvguard: [%s (%d)] Suspension "
					"expired.\n", name, td->td_proc->p_pid);
			se->se_ncrashes = 1;
			se->se_expiry = sbt + ((pr != NULL) ? pr->pr_pax_segvguard_expiry : pax_segvguard_expiry) * SBT_1S;
			se->se_suspended = 0;

			mtx_unlock(&segvguard_mtx);
			return (0);
		}

		se->se_ncrashes++;

		if (se->se_ncrashes >= pax_segvguard_maxcrashes) {
			printf("PaX Segvguard: [%s (%d)] Suspending "
					"execution for %d seconds after %zu crashes.\n",
					name, td->td_proc->p_pid,
					pax_segvguard_suspension, se->se_ncrashes);
			se->se_suspended = sbt + ((pr != NULL) ? pr->pr_pax_segvguard_suspension : pax_segvguard_suspension) * SBT_1S;
			se->se_ncrashes = 0;
			se->se_expiry = 0;
		}

		mtx_unlock(&segvguard_mtx);
		return (0);
	}

	mtx_unlock(&segvguard_mtx);
	return (0);
}

static void
pax_segvguard_init(void)
{

	mtx_init(&segvguard_mtx, "segvguard mutex", NULL, MTX_DEF);

	pax_segvguard_hashtbl = hashinit(pax_segvguard_hashsize, M_PAX, &pax_segvguard_hashmask);
}

SYSINIT(pax_segvguard_init, SI_SUB_LOCK, SI_ORDER_ANY, pax_segvguard_init, NULL);
