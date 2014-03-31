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

#include "opt_pax.h"
#include "opt_compat.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/imgact.h>
#include <sys/sysent.h>
#include <sys/proc.h>
#include <sys/elf_common.h>
#include <sys/pax.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/libkern.h>
#include <sys/jail.h>

#include <sys/mman.h>
#include <sys/libkern.h>
#include <sys/exec.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>

static int sysctl_pax_aslr_status(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_mmap(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_stack(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_exec(SYSCTL_HANDLER_ARGS);

/*
 * sysctls and tunables
 */
int pax_aslr_status = PAX_ASLR_ENABLED;
int pax_aslr_debug = 0;

#ifdef PAX_ASLR_MAX_SEC
int pax_aslr_mmap_len = PAX_ASLR_DELTA_MMAP_MAX_LEN;
int pax_aslr_stack_len = PAX_ASLR_DELTA_STACK_MAX_LEN;
int pax_aslr_exec_len = PAX_ASLR_DELTA_EXEC_MAX_LEN;
#else
int pax_aslr_mmap_len = PAX_ASLR_DELTA_MMAP_MIN_LEN;
int pax_aslr_stack_len = PAX_ASLR_DELTA_STACK_MIN_LEN;
int pax_aslr_exec_len = PAX_ASLR_DELTA_EXEC_MIN_LEN;
#endif /* PAX_ASLR_MAX_SEC */


SYSCTL_NODE(_security, OID_AUTO, pax, CTLFLAG_RD, 0,
    "PaX (exploit mitigation) features.");
SYSCTL_NODE(_security_pax, OID_AUTO, aslr, CTLFLAG_RD, 0,
    "Address Space Layout Randomization.");

SYSCTL_PROC(_security_pax_aslr, OID_AUTO, status,
    CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_TUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_status, "I",
    "Restrictions status. "
    "0 - disabled, "
    "1 - enabled,  "
    "2 - global enabled, "
    "3 - force global enabled");
TUNABLE_INT("security.pax.aslr.status", &pax_aslr_status);

SYSCTL_INT(_security_pax_aslr, OID_AUTO, debug, CTLFLAG_RWTUN|CTLFLAG_PRISON, &pax_aslr_debug, 0, "ASLR debug mode");
TUNABLE_INT("security.pax.aslr.debug", &pax_aslr_debug);

SYSCTL_PROC(_security_pax_aslr, OID_AUTO, mmap_len,
    CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_TUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_mmap, "I",
    "Number of bits randomized for mmap(2) calls. "
    "32 bit: [8,16] 64 bit: [16,32]");
TUNABLE_INT("security.pax.aslr.mmap_len", &pax_aslr_mmap_len);

SYSCTL_PROC(_security_pax_aslr, OID_AUTO, stack_len,
    CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_TUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_stack, "I",
    "Number of bits randomized for the stack. "
    "32 bit: [6,12] 64 bit: [12,21]");
TUNABLE_INT("security.pax.aslr.stack_len", &pax_aslr_stack_len);

SYSCTL_PROC(_security_pax_aslr, OID_AUTO, exec_len,
    CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_TUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_exec, "I",
    "Number of bits randomized for the PIE exec base. "
    "32 bit: [6,12] 64 bit: [12,21]");
TUNABLE_INT("security.pax.aslr.exec_len", &pax_aslr_exec_len);

static int
sysctl_pax_aslr_status(SYSCTL_HANDLER_ARGS)
{
    int err;
    int val;
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(req->td, NULL);

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    val = (pr != NULL) ? pr->pr_pax_aslr_status : pax_aslr_status;
    err = sysctl_handle_int(oidp, &val, sizeof(int), req);
    if (err || !req->newptr)
        return (err);

    switch (val) {
        case    PAX_ASLR_DISABLED:
        case    PAX_ASLR_ENABLED:
        case    PAX_ASLR_GLOBAL_ENABLED:
        case    PAX_ASLR_FORCE_GLOBAL_ENABLED:
            pax_aslr_status = val;
            if (pr)
                pr->pr_pax_aslr_status = val;
            break;
        default:
            return (EINVAL);
    }

    return (0);
}

static int
sysctl_pax_aslr_mmap(SYSCTL_HANDLER_ARGS)
{
    int err;
    int val;
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(req->td, NULL);

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    val = (pr != NULL) ? pr->pr_pax_aslr_mmap_len : pax_aslr_mmap_len;
    err = sysctl_handle_int(oidp, &val, sizeof(int), req);
    if (err || !req->newptr)
        return (err);

    if (val < PAX_ASLR_DELTA_MMAP_MIN_LEN
        || val > PAX_ASLR_DELTA_MMAP_MAX_LEN)
        return (EINVAL);

    pax_aslr_mmap_len = val;
    if (pr)
        pr->pr_pax_aslr_mmap_len = val;

    return (0);
}

static int
sysctl_pax_aslr_stack(SYSCTL_HANDLER_ARGS)
{
    int err;
    int val;
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(req->td, NULL);

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    val = (pr != NULL) ? pr->pr_pax_aslr_stack_len : pax_aslr_stack_len;
    err = sysctl_handle_int(oidp, &val, sizeof(int), req);
    if (err || !req->newptr)
        return (err);

    if (val < PAX_ASLR_DELTA_STACK_MIN_LEN
        || val > PAX_ASLR_DELTA_STACK_MAX_LEN)
        return (EINVAL);

    pax_aslr_stack_len = val;
    if (pr)
        pr->pr_pax_aslr_stack_len = val;

    return (0);
}

static int
sysctl_pax_aslr_exec(SYSCTL_HANDLER_ARGS)
{
    int err;
    int val;
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(req->td, NULL);

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    val = (pr != NULL) ? pr->pr_pax_aslr_exec_len : pax_aslr_exec_len;
    err = sysctl_handle_int(oidp, &val, sizeof(int), req);
    if (err || !req->newptr)
        return (err);

    if (val < PAX_ASLR_DELTA_EXEC_MIN_LEN
        || val > PAX_ASLR_DELTA_EXEC_MAX_LEN)
        return (EINVAL);

    pax_aslr_exec_len = val;
    if (pr)
        pr->pr_pax_aslr_exec_len = val;

    return (0);
}

/*
 * COMPAT_FREEBSD32 and linuxulator..
 */
#ifdef COMPAT_FREEBSD32
int pax_aslr_compat_status = PAX_ASLR_ENABLED;

static int sysctl_pax_aslr_compat_status(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_compat_mmap(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_compat_stack(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_aslr_compat_exec(SYSCTL_HANDLER_ARGS);

#ifdef PAX_ASLR_MAX_SEC
int pax_aslr_compat_mmap_len = PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN;
int pax_aslr_compat_stack_len = PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN;
int pax_aslr_compat_exec_len = PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN;
#else
int pax_aslr_compat_mmap_len = PAX_ASLR_COMPAT_DELTA_MMAP_MIN_LEN;
int pax_aslr_compat_stack_len = PAX_ASLR_COMPAT_DELTA_STACK_MIN_LEN;
int pax_aslr_compat_exec_len = PAX_ASLR_COMPAT_DELTA_EXEC_MIN_LEN;
#endif /* PAX_ASLR_MAX_SEC */

SYSCTL_NODE(_security_pax_aslr, OID_AUTO, compat, CTLFLAG_RD, 0,
    "Setting for COMPAT_FREEBSD32 and linuxulator.");

SYSCTL_PROC(_security_pax_aslr_compat, OID_AUTO, status,
    CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_TUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_compat_status, "I",
    "Restrictions status. "
    "0 - disabled, "
    "1 - enabled,  "
    "2 - global enabled, "
    "3 - force global enabled");
TUNABLE_INT("security.pax.aslr.compat.status", &pax_aslr_compat_status);

SYSCTL_PROC(_security_pax_aslr_compat, OID_AUTO, mmap_len,
    CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_TUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_compat_mmap, "I",
    "Number of bits randomized for mmap(2) calls. "
    "32 bit: [8,16]");
TUNABLE_INT("security.pax.aslr.compat.mmap", &pax_aslr_compat_mmap_len);

SYSCTL_PROC(_security_pax_aslr_compat, OID_AUTO, stack_len,
    CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_TUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_compat_stack, "I",
    "Number of bits randomized for the stack. "
    "32 bit: [6,12]");
TUNABLE_INT("security.pax.aslr.compat.stack", &pax_aslr_compat_stack_len);

SYSCTL_PROC(_security_pax_aslr_compat, OID_AUTO, exec_len,
    CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_TUN|CTLFLAG_PRISON,
    NULL, 0, sysctl_pax_aslr_compat_exec, "I",
    "Number of bits randomized for the PIE exec base. "
    "32 bit: [6,12]");
TUNABLE_INT("security.pax.aslr.compat.stack", &pax_aslr_compat_exec_len);


static int
sysctl_pax_aslr_compat_status(SYSCTL_HANDLER_ARGS)
{
    int err;
    int val, *ptr;
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(req->td, NULL);
    ptr = (pr != NULL) ? &(pr->pr_pax_aslr_compat_status) : &pax_aslr_compat_status;

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    val = *ptr;
    err = sysctl_handle_int(oidp, &val, sizeof(int), req);
    if (err || !req->newptr)
        return (err);

    switch (val) {
        case    PAX_ASLR_DISABLED:
        case    PAX_ASLR_ENABLED:
        case    PAX_ASLR_GLOBAL_ENABLED:
        case    PAX_ASLR_FORCE_GLOBAL_ENABLED:
            pax_aslr_compat_status = val;
            *ptr = val;
            break;
        default:
            return (EINVAL);
    }

    return (0);
}

static int
sysctl_pax_aslr_compat_mmap(SYSCTL_HANDLER_ARGS)
{
    int err;
    int val, *ptr;
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(req->td, NULL);
    ptr = (pr != NULL) ? &(pr->pr_pax_aslr_compat_mmap_len) : &pax_aslr_compat_mmap_len;

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    val = *ptr;
    err = sysctl_handle_int(oidp, &val, sizeof(int), req);
    if (err || !req->newptr)
        return (err);

    if (val < PAX_ASLR_COMPAT_DELTA_MMAP_MIN_LEN
        || val > PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN)
        return (EINVAL);

    pax_aslr_compat_mmap_len = val;
    *ptr = val;

    return (0);
}

static int
sysctl_pax_aslr_compat_stack(SYSCTL_HANDLER_ARGS)
{
    int err;
    int val, *ptr;
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(req->td, NULL);
    ptr = (pr != NULL) ? &(pr->pr_pax_aslr_compat_stack_len) : &pax_aslr_compat_stack_len;

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    val = (pr != NULL) ? pr->pr_pax_aslr_compat_stack_len : pax_aslr_compat_stack_len;
    err = sysctl_handle_int(oidp, &val, sizeof(int), req);
    if (err || !req->newptr)
        return (err);

    if (val < PAX_ASLR_COMPAT_DELTA_STACK_MIN_LEN
        || val > PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN)
        return (EINVAL);

    pax_aslr_compat_stack_len = val;
    *ptr = val;

    return (0);
}

static int
sysctl_pax_aslr_compat_exec(SYSCTL_HANDLER_ARGS)
{
    int err;
    int val, *ptr;
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(req->td, NULL);
    ptr = (pr != NULL) ? &(pr->pr_pax_aslr_compat_exec_len) : &pax_aslr_compat_exec_len;

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    val = *ptr;
    err = sysctl_handle_int(oidp, &val, sizeof(int), req);
    if (err || !req->newptr)
        return (err);

    if (val < PAX_ASLR_COMPAT_DELTA_EXEC_MIN_LEN
        || val > PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN)
        return (EINVAL);

    pax_aslr_compat_exec_len = val;
    *ptr = val;

    return (0);
}
#endif /* COMPAT_FREEBSD32 */


/*
 * ASLR functions
 */
bool
pax_aslr_active(struct thread *td, struct proc *proc)
{
    int status;
    struct prison *pr=NULL;
#ifdef  notyet
    uint32_t    flags;
#endif /* notyet */

    if (!(td) && !(proc))
        return (true);

#ifdef notyet
    flags = (td != NULL) ? td->td_proc->p_pax : proc->p_pax;
#endif /* notyet */
    pr = pax_aslr_get_prison(td, proc);

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    status = (pr != NULL) ? pr->pr_pax_aslr_status : pax_aslr_status;

    switch (status) {
    case    PAX_ASLR_DISABLED:
        return (false);
    case    PAX_ASLR_FORCE_GLOBAL_ENABLED:
        return (true);
    case    PAX_ASLR_ENABLED:
#ifdef notyet
        if ((flags & ELF_NOTE_PAX_ASLR) == 0)
            return (false);
#endif /* notyet */
        break;
    case    PAX_ASLR_GLOBAL_ENABLED:
#ifdef notyet
        if ((flags & ELF_NOTE_PAX_NOASLR) != 0)
            return (false);
#endif /* notyet */
        break;
    default:
        return (true);
    }

    return (true);
}

struct prison *
pax_aslr_get_prison(struct thread *td, struct proc *proc)
{
    if ((td)) {
        if ((td->td_proc) && (td->td_proc->p_ucred))
            return td->td_proc->p_ucred->cr_prison;

        return NULL;
    }

    if (!(proc))
        return NULL;

    return proc->p_ucred->cr_prison;
}

void
pax_aslr_init_prison(struct prison *pr)
{
    if (!(pr))
        return;

    if (pr->pr_pax_set)
        return;

    if (pax_aslr_debug)
        uprintf("[PaX ASLR] pax_aslr_init_prison: Setting prison %s ASLR variables\n", pr->pr_name);

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

    pr->pr_pax_set = 1;
}

void
pax_aslr_init(struct thread *td, struct image_params *imgp)
{
    struct vmspace *vm;
    u_int sv_flags;
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(td, NULL);

    if ((pr) && !(pr->pr_pax_set))
        pax_aslr_init_prison(pr);

    if (imgp == NULL) {
        panic("[PaX ASLR] pax_aslr_init - imgp == NULL");
    }

    if (!pax_aslr_active(td, NULL))
        return;

    vm = imgp->proc->p_vmspace;
    sv_flags = imgp->proc->p_sysent->sv_flags;

#ifndef COMPAT_FREEBSD32
    vm->vm_aslr_delta_mmap = PAX_ASLR_DELTA(arc4random(),
        PAX_ASLR_DELTA_MMAP_LSB, (pr != NULL) ? pr->pr_pax_aslr_mmap_len : pax_aslr_mmap_len);
    vm->vm_aslr_delta_stack = PAX_ASLR_DELTA(arc4random(),
        PAX_ASLR_DELTA_STACK_LSB, (pr != NULL) ? pr->pr_pax_aslr_stack_len : pax_aslr_stack_len);
    vm->vm_aslr_delta_stack = ALIGN(vm->vm_aslr_delta_stack);
#else /* COMPAT_FREEBSD32 */
    if ((sv_flags & SV_LP64) != 0) {
        vm->vm_aslr_delta_mmap = PAX_ASLR_DELTA(arc4random(),
            PAX_ASLR_DELTA_MMAP_LSB, (pr != NULL) ? pr->pr_pax_aslr_mmap_len : pax_aslr_mmap_len);
        vm->vm_aslr_delta_stack = PAX_ASLR_DELTA(arc4random(),
            PAX_ASLR_DELTA_STACK_LSB, (pr != NULL) ? pr->pr_pax_aslr_stack_len : pax_aslr_stack_len);
        vm->vm_aslr_delta_stack = ALIGN(vm->vm_aslr_delta_stack);
    } else {
        vm->vm_aslr_delta_mmap = PAX_ASLR_DELTA(arc4random(),
            PAX_ASLR_COMPAT_DELTA_MMAP_LSB, (pr != NULL) ? pr->pr_pax_aslr_compat_mmap_len : pax_aslr_compat_mmap_len);
        vm->vm_aslr_delta_stack = PAX_ASLR_DELTA(arc4random(),
            PAX_ASLR_COMPAT_DELTA_STACK_LSB, (pr != NULL) ? pr->pr_pax_aslr_compat_stack_len : pax_aslr_compat_stack_len);
        vm->vm_aslr_delta_stack = ALIGN(vm->vm_aslr_delta_stack);
    }
#endif /* !COMPAT_FREEBSD32 */
}

void
pax_aslr_mmap(struct thread *td, vm_offset_t *addr, vm_offset_t orig_addr, int flags)
{
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(td, NULL);

    if (!pax_aslr_active(td, NULL))
        return;

    if (!(flags & MAP_FIXED) && ((orig_addr == 0) || !(flags & MAP_ANON))) {
        if (pax_aslr_debug)
            uprintf("[PaX ASLR] applying to %p orig_addr=%p f=%x\n",
                (void *)*addr, (void *)orig_addr, flags);
        if (!(td->td_proc->p_vmspace->vm_map.flags & MAP_ENTRY_GROWS_DOWN))
            *addr += td->td_proc->p_vmspace->vm_aslr_delta_mmap;
        else
            *addr -= td->td_proc->p_vmspace->vm_aslr_delta_mmap;
        if (pax_aslr_debug)
            uprintf("[PaX ASLR] result %p\n", (void *)*addr);
    }
    else if (pax_aslr_debug)
        uprintf("[PaX ASLR] not applying to %p orig_addr=%p f=%x\n",
        (void *)*addr, (void *)orig_addr, flags);
}

void
pax_aslr_stack(struct thread *td, uintptr_t *addr, uintptr_t orig_addr)
{
    struct prison *pr=NULL;

    pr = pax_aslr_get_prison(td, NULL);

    if (!pax_aslr_active(td, NULL))
        return;

    *addr -= td->td_proc->p_vmspace->vm_aslr_delta_stack;
    if ((pr) && pr->pr_pax_aslr_debug)
        uprintf("[PaX ASLR] orig_addr=%p, addr=%p\n",
            (void *)orig_addr, (void *)*addr);
}
