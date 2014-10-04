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

#ifndef	__SYS_PAX_H
#define	__SYS_PAX_H

#ifdef _KERNEL

struct image_params;
struct prison;
struct thread;
struct proc;
struct vnode;
struct vmspace;
struct vm_offset_t;

/*
 * used in sysctl handler
 */
#define	PAX_FEATURE_DISABLED		0
#define	PAX_FEATURE_OPTIN		1
#define	PAX_FEATURE_OPTOUT		2
#define	PAX_FEATURE_FORCE_ENABLED	3
#define	PAX_FEATURE_UNKNOWN_STATUS	4

extern const char *pax_status_str[];

#define PAX_FEATURE_SIMPLE_DISABLED	0
#define PAX_FEATURE_SIMPLE_ENABLED	1

extern const char *pax_status_simple_str[];

#ifndef PAX_ASLR_DELTA
#define	PAX_ASLR_DELTA(delta, lsb, len)	\
	(((delta) & ((1UL << (len)) - 1)) << (lsb))
#endif /* PAX_ASLR_DELTA */

/*
 * generic ASLR values
 *
 *  	MMAP	| 32 bit | 64 bit |
 * 	+-------+--------+--------+
 * 	| MIN	|  8 bit | 16 bit |
 * 	+-------+--------+--------+
 * 	| DEF	| 14 bit | 21 bit |
 * 	+-------+--------+--------+
 * 	| MAX   | 20 bit | 32 bit |
 * 	+-------+--------+--------+
 *
 *  	STACK	| 32 bit | 64 bit |
 * 	+-------+--------+--------+
 * 	| MIN	|  6 bit | 12 bit |
 * 	+-------+--------+--------+
 * 	| DEF	|  6 bit | 16 bit |
 * 	+-------+--------+--------+
 * 	| MAX   | 10 bit | 21 bit |
 * 	+-------+--------+--------+
 *
 *  	EXEC	| 32 bit | 64 bit |
 * 	+-------+--------+--------+
 * 	| MIN	|  6 bit | 12 bit |
 * 	+-------+--------+--------+
 * 	| DEF	| 14 bit | 21 bit |
 * 	+-------+--------+--------+
 * 	| MAX   | 20 bit | 21 bit |
 * 	+-------+--------+--------+
 *
 */
#ifndef PAX_ASLR_DELTA_MMAP_LSB
#define PAX_ASLR_DELTA_MMAP_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_DELTA_MMAP_LSB */

#ifndef PAX_ASLR_DELTA_MMAP_MIN_LEN
#define PAX_ASLR_DELTA_MMAP_MIN_LEN	((sizeof(void *) * NBBY) / 4)
#endif /* PAX_ASLR_DELTA_MMAP_MAX_LEN */

#ifndef PAX_ASLR_DELTA_MMAP_MAX_LEN
#ifdef __LP64__
#define PAX_ASLR_DELTA_MMAP_MAX_LEN	((sizeof(void *) * NBBY) / 2)
#else
#define PAX_ASLR_DELTA_MMAP_MAX_LEN 20
#endif /* __LP64__ */
#endif /* PAX_ASLR_DELTA_MMAP_MAX_LEN */

#ifndef PAX_ASLR_DELTA_STACK_LSB
#define PAX_ASLR_DELTA_STACK_LSB	3
#endif /* PAX_ASLR_DELTA_STACK_LSB */

#ifndef PAX_ASLR_DELTA_STACK_MIN_LEN
#define PAX_ASLR_DELTA_STACK_MIN_LEN	((sizeof(void *) * NBBY) / 5)
#endif /* PAX_ASLR_DELTA_STACK_MAX_LEN */

#ifndef PAX_ASLR_DELTA_STACK_MAX_LEN
#define PAX_ASLR_DELTA_STACK_MAX_LEN	((sizeof(void *) * NBBY) / 3)
#endif /* PAX_ASLR_DELTA_STACK_MAX_LEN */

#ifndef PAX_ASLR_DELTA_EXEC_LSB
#define PAX_ASLR_DELTA_EXEC_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_DELTA_EXEC_LSB */

#ifndef PAX_ASLR_DELTA_EXEC_MIN_LEN
#define PAX_ASLR_DELTA_EXEC_MIN_LEN	((sizeof(void *) * NBBY) / 5)
#endif /* PAX_ASLR_DELTA_EXEC_MIN_LEN */

#ifndef PAX_ASLR_DELTA_EXEC_MAX_LEN
#ifdef __LP64__
#define PAX_ASLR_DELTA_EXEC_MAX_LEN	((sizeof(void *) * NBBY) / 3)
#else
#define PAX_ASLR_DELTA_EXEC_MAX_LEN 20
#endif /* __LP64__ */
#endif /* PAX_ASLR_DELTA_EXEC_MAX_LEN */

/*
 * ASLR default values for native host
 */
#ifdef __LP64__
#ifndef PAX_ASLR_DELTA_MMAP_DEF_LEN
#define PAX_ASLR_DELTA_MMAP_DEF_LEN	21
#endif /* PAX_ASLR_DELTA_MMAP_DEF_LEN */
#ifndef PAX_ASLR_DELTA_STACK_DEF_LEN
#define PAX_ASLR_DELTA_STACK_DEF_LEN	16
#endif /* PAX_ASLR_DELTA_STACK_DEF_LEN */
#ifndef PAX_ASLR_DELTA_EXEC_DEF_LEN
#define PAX_ASLR_DELTA_EXEC_DEF_LEN	21
#endif /* PAX_ASLR_DELTA_EXEC_DEF_LEN */
#else
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
 * ASLR values for COMPAT_FREEBSD32 and COMPAT_LINUX
 */
#ifndef PAX_ASLR_COMPAT_DELTA_MMAP_LSB
#define PAX_ASLR_COMPAT_DELTA_MMAP_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_COMPAT_DELTA_MMAP_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_MMAP_MIN_LEN
#define PAX_ASLR_COMPAT_DELTA_MMAP_MIN_LEN	((sizeof(int) * NBBY) / 4)
#endif /* PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN
#define PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN	((sizeof(int) * NBBY) / 2)
#endif /* PAX_ASLR_COMPAT_DELTA_MMAP_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_STACK_LSB
#define PAX_ASLR_COMPAT_DELTA_STACK_LSB		3
#endif /* PAX_ASLR_COMPAT_DELTA_STACK_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_STACK_MIN_LEN
#define PAX_ASLR_COMPAT_DELTA_STACK_MIN_LEN	((sizeof(int) * NBBY) / 5)
#endif /* PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN
#define PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN	((sizeof(int) * NBBY) / 3)
#endif /* PAX_ASLR_COMPAT_DELTA_STACK_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_EXEC_LSB
#define PAX_ASLR_COMPAT_DELTA_EXEC_LSB		PAGE_SHIFT
#endif /* PAX_ASLR_COMPAT_DELTA_EXEC_LSB */

#ifndef PAX_ASLR_COMPAT_DELTA_EXEC_MIN_LEN
#define PAX_ASLR_COMPAT_DELTA_EXEC_MIN_LEN	((sizeof(int) * NBBY) / 5)
#endif /* PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN */

#ifndef PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN
#define PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN	((sizeof(int) * NBBY) / 3)
#endif /* PAX_ASLR_COMPAT_DELTA_EXEC_MAX_LEN */

extern int pax_aslr_status;
extern int pax_aslr_debug;

extern int pax_aslr_mmap_len;
extern int pax_aslr_stack_len;
extern int pax_aslr_exec_len;
#ifdef COMPAT_FREEBSD32
extern int pax_aslr_compat_status;
extern int pax_aslr_compat_mmap_len;
extern int pax_aslr_compat_stack_len;
extern int pax_aslr_compat_exec_len;
#endif /* COMPAT_FREEBSD32 */

#ifdef PAX_SEGVGUARD
extern int pax_segvguard_status;
extern int pax_segvguard_debug;
extern int pax_segvguard_expiry;
extern int pax_segvguard_suspension;
extern int pax_segvguard_maxcrashes;
#endif /* PAX_SEGVGUARD */

#ifdef PAX_HARDENING
extern int pax_map32_enabled_global;
#endif /* PAX_HARDENING*/

extern int hardening_log_log;
extern int hardening_log_ulog;

#define PAX_NOTE_MPROTECT	0x00000001
#define PAX_NOTE_NOMPROTECT	0x00000002
#define PAX_NOTE_SEGVGUARD	0x00000004
#define PAX_NOTE_NOSEGVGUARD	0x00000008
#define PAX_NOTE_ASLR		0x00000010
#define PAX_NOTE_NOASLR		0x00000020

#define PAX_NOTE_RESERVED0	0x40000000
#define PAX_NOTE_FINALIZED	0x80000000

#define PAX_NOTE_ALL_ENABLED	\
			(PAX_NOTE_MPROTECT | PAX_NOTE_SEGVGUARD | PAX_NOTE_ASLR)
#define PAX_NOTE_ALL_DISABLED	\
			(PAX_NOTE_NOMPROTECT | PAX_NOTE_NOSEGVGUARD | PAX_NOTE_NOASLR)
#define PAX_NOTE_ALL	(PAX_NOTE_ALL_ENABLED | PAX_NOTE_ALL_DISABLED)

#define HARDENING_LOG_LOG		PAX_FEATURE_DISABLED
#define HARDENING_LOG_ULOG		PAX_FEATURE_SIMPLE_DISABLED

#define PAX_SEGVGUARD_EXPIRY		(2 * 60)
#define PAX_SEGVGUARD_SUSPENSION	(10 * 60)
#define PAX_SEGVGUARD_MAXCRASHES	5

/*
 * generic pax functions
 */
int pax_elf(struct image_params *, uint32_t);
int pax_get_flags(struct proc *proc, uint32_t *flags);
struct prison *pax_get_prison(struct proc *proc);
void pax_init_prison(struct prison *pr);

/*
 * ASLR related functions
 */
bool pax_aslr_active(struct proc *proc);
void _pax_aslr_init(struct vmspace *vm, struct proc *p);
void _pax_aslr_init32(struct vmspace *vm, struct proc *p);
void pax_aslr_init(struct image_params *imgp);
void pax_aslr_mmap(struct proc *p, vm_offset_t *addr, 
    vm_offset_t orig_addr, int flags);
u_int pax_aslr_setup_flags(struct image_params *imgp, u_int mode);
void pax_aslr_stack(struct thread *td, uintptr_t *addr);

/*
 * Log related functions
 */
int hbsd_uprintf(const char *fmt, ...);
void pax_log_aslr(struct proc *, const char *func, const char *fmt, ...);
void pax_ulog_aslr(const char *func, const char *fmt, ...);
void pax_log_segvguard(struct proc *, const char *func, const char *fmt, ...);
void pax_ulog_segvguard(const char *func, const char *fmt, ...);

/*
 * SegvGuard related functions
 */
int pax_segvguard_check(struct thread *, struct vnode *, const char *);
int pax_segvguard_segfault(struct thread *, const char *);
void pax_segvguard_remove(struct thread *td, struct vnode *vn);
u_int pax_segvguard_setup_flags(struct image_params *imgp, u_int mode);
int pax_segvguard_update_flags_if_setuid(struct image_params *imgp,
    struct vnode *vn);

/*
 * Hardening related functions
 */
int pax_map32_enabled(struct thread *td);
int pax_mprotect_exec_enabled(void);

#endif /* _KERNEL */

#endif /* __SYS_PAX_H */
