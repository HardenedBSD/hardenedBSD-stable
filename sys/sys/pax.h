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
struct vnode;
struct vmspace;
struct vm_offset_t;

/*
 * used in sysctl handler
 */
#define PAX_ASLR_DISABLED	0
#define PAX_ASLR_OPTIN		1
#define PAX_ASLR_OPTOUT		2
#define PAX_ASLR_FORCE_ENABLED	3

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
 * 	| DEF	|  8 bit | 21 bit |
 * 	+-------+--------+--------+
 * 	| MAX   | 16 bit | 32 bit |
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
 * 	| DEF	|  6 bit | 21 bit |
 * 	+-------+--------+--------+
 * 	| MAX   | 10 bit | 21 bit |
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
#define PAX_ASLR_DELTA_MMAP_MAX_LEN	((sizeof(void *) * NBBY) / 2)
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
#endif /* PAX_ASLR_DELTA_EXEC_MAX_LEN */

#ifndef PAX_ASLR_DELTA_EXEC_MAX_LEN
#define PAX_ASLR_DELTA_EXEC_MAX_LEN	((sizeof(void *) * NBBY) / 3)
#endif /* PAX_ASLR_DELTA_EXEC_MAX_LEN */

/*
 * ASLR default values for native host
 */
#ifdef __amd64__
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
#define PAX_ASLR_DELTA_MMAP_DEF_LEN	PAX_ASLR_DELTA_MMAP_MIN_LEN
#endif /* PAX_ASLR_DELTA_MMAP_DEF_LEN */
#ifndef PAX_ASLR_DELTA_STACK_DEF_LEN
#define PAX_ASLR_DELTA_STACK_DEF_LEN	PAX_ASLR_DELTA_STACK_MIN_LEN
#endif /* PAX_ASLR_DELTA_STACK_DEF_LEN */
#ifndef PAX_ASLR_DELTA_EXEC_DEF_LEN
#define PAX_ASLR_DELTA_EXEC_DEF_LEN	PAX_ASLR_DELTA_EXEC_MIN_LEN
#endif /* PAX_ASLR_DELTA_EXEC_DEF_LEN */
#endif /* __amd64__ */

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

extern int pax_log_log;
extern int pax_log_ulog;

#define ELF_NOTE_TYPE_PAX_TAG   3
#define PAX_NOTE_MPROTECT   0x01
#define PAX_NOTE_NOMPROTECT 0x02
#define PAX_NOTE_GUARD      0x04
#define PAX_NOTE_NOGUARD    0x08
#define PAX_NOTE_ASLR       0x10
#define PAX_NOTE_NOASLR     0x20

#define PAX_LOG_LOG		0
#define PAX_LOG_ULOG		0

void pax_init(void);
void pax_init_prison(struct prison *pr);
bool pax_aslr_active(struct thread *td, struct proc *proc);
void _pax_aslr_init(struct vmspace *vm, struct prison *pr);
void _pax_aslr_init32(struct vmspace *vm, struct prison *pr);
void pax_aslr_init(struct thread *td, struct image_params *imgp);
void pax_aslr_mmap(struct thread *td, vm_offset_t *addr, 
    vm_offset_t orig_addr, int flags);
void pax_aslr_stack(struct thread *td, uintptr_t *addr);
struct prison *pax_get_prison(struct thread *td, struct proc *proc);
void pax_elf(struct image_params *, uint32_t);

void pax_log_aslr(const char *func, const char *fmt, ...);
void pax_ulog_aslr(const char *func, const char *fmt, ...);

#endif /* _KERNEL */

#endif /* __SYS_PAX_H */
