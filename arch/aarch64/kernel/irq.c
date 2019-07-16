/*
 * Copyright (c) 2014-2018, Stefan Lankes, RWTH Aachen University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the University nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <hermit/stdlib.h>
#include <hermit/stdio.h>
#include <hermit/logging.h>
#include <hermit/errno.h>
#include <hermit/tasks.h>
#include <hermit/spinlock.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <asm/irq.h>
#include <asm/linux_syscalls.h>

/* GIC related constants */
#define GICR_BASE			0

/* GIC Distributor interface register offsets that are common to GICv3 & GICv2 */
#define GICD_CTLR			0x0
#define GICD_TYPER			0x4
#define GICD_IIDR			0x8
#define GICD_IGROUPR			0x80
#define GICD_ISENABLER			0x100
#define GICD_ICENABLER			0x180
#define GICD_ISPENDR			0x200
#define GICD_ICPENDR			0x280
#define GICD_ISACTIVER			0x300
#define GICD_ICACTIVER			0x380
#define GICD_IPRIORITYR			0x400
#define GICD_ITARGETSR			0x800
#define GICD_ICFGR			0xc00
#define GICD_NSACR			0xe00
#define GICD_SGIR			0xF00

#define GICD_CTLR_ENABLEGRP0		(1 << 0)
#define GICD_CTLR_ENABLEGRP1		(1 << 1)

/* Physical CPU Interface registers */
#define GICC_CTLR			0x0
#define GICC_PMR			0x4
#define GICC_BPR			0x8
#define GICC_IAR			0xC
#define GICC_EOIR			0x10
#define GICC_RPR			0x14
#define GICC_HPPIR			0x18
#define GICC_AHPPIR			0x28
#define GICC_IIDR			0xFC
#define GICC_DIR			0x1000
#define GICC_PRIODROP			GICC_EOIR

#define GICC_CTLR_ENABLEGRP0		(1 << 0)
#define GICC_CTLR_ENABLEGRP1		(1 << 1)
#define GICC_CTLR_FIQEN			(1 << 3)
#define GICC_CTLR_ACKCTL		(1 << 2)

#define MAX_HANDLERS			256
#define RESCHED_INT			1

/** @brief IRQ handle pointers
*
* This array is actually an array of function pointers. We use
* this to handle custom IRQ handlers for a given IRQ
*/
static irq_handler_t irq_routines[MAX_HANDLERS] = {[0 ... MAX_HANDLERS-1] = NULL};

static spinlock_irqsave_t mask_lock = SPINLOCK_IRQSAVE_INIT;

static size_t gicd_base = GICD_BASE;
static size_t gicc_base = GICC_BASE;
static uint32_t nr_irqs = 0;

static inline uint32_t gicd_read(size_t off)
{
	uint32_t value;
	asm volatile("ldar %w0, [%1]" : "=r"(value) : "r"(gicd_base + off) : "memory");
	return value;
}

static inline void gicd_write(size_t off, uint32_t value)
{
	asm volatile("str %w0, [%1]" : : "rZ" (value), "r" (gicd_base + off) : "memory");
}

static inline uint32_t gicc_read(size_t off)
{
	uint32_t value;
	asm volatile("ldar %w0, [%1]" : "=r"(value) : "r"(gicc_base + off) : "memory");
	return value;
}

static inline void gicc_write(size_t off, uint32_t value)
{
	asm volatile("str %w0, [%1]" : : "rZ" (value), "r" (gicc_base + off) : "memory");
}

static void gicc_enable(void)
{
	// Global enable signalling of interrupt from the cpu interface
	gicc_write(GICC_CTLR, GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1 | GICC_CTLR_FIQEN | GICC_CTLR_ACKCTL);
}

static void gicc_disable(void)
{
	// Global disable signalling of interrupt from the cpu interface
	gicc_write(GICC_CTLR, 0);
}

static void gicd_enable(void)
{
	// Global enable forwarding interrupts from distributor to cpu interface
	gicd_write(GICD_CTLR, GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1);
}

static void gicd_disable(void)
{
	// Global disable forwarding interrupts from distributor to cpu interface
	gicd_write(GICD_CTLR, 0);
}

static void gicc_set_priority(uint32_t priority)
{
	gicc_write(GICC_PMR, priority & 0xFF);
}

static void gic_set_enable(uint32_t vector, uint8_t enable)
{
	if (enable) {
		uint32_t regoff = GICD_ISENABLER + 4 * (vector / 32);
		gicd_write(regoff, gicd_read(regoff) | (1 << (vector % 32)));
	} else {
		uint32_t regoff = GICD_ICENABLER + 4 * (vector / 32);
		gicd_write(regoff, gicd_read(regoff) | (1 << (vector % 32)));
	}
}

static int unmask_interrupt(uint32_t vector)
{
	if (vector >= nr_irqs)
		return -EINVAL;

	spinlock_irqsave_lock(&mask_lock);
	gic_set_enable(vector, 1);
	spinlock_irqsave_unlock(&mask_lock);

	return 0;
}

static int mask_interrupt(uint32_t vector)
{
	if (vector >= nr_irqs)
		return -EINVAL;

	spinlock_irqsave_lock(&mask_lock);
	gic_set_enable(vector, 0);
	spinlock_irqsave_unlock(&mask_lock);

	return 0;
}

/* This installs a custom IRQ handler for the given IRQ */
int irq_install_handler(unsigned int irq, irq_handler_t handler)
{
	if (irq >= MAX_HANDLERS)
		return -EINVAL;

	irq_routines[irq] = handler;
	
	unmask_interrupt(irq);

	return 0;
}

/* This clears the handler for a given IRQ */
int irq_uninstall_handler(unsigned int irq)
{
	if (irq >= MAX_HANDLERS)
		return -EINVAL;

	irq_routines[irq] = NULL;

	mask_interrupt(irq);

	return 0;
}

int irq_post_init(void)
{
	int ret;

	LOG_INFO("Enable interrupt handling\n");

	ret = vma_add(GICD_BASE, GICD_BASE+GIC_SIZE, VMA_READ|VMA_WRITE);
	if (BUILTIN_EXPECT(ret, 0))
		goto oom;

	ret = page_map(gicd_base, GICD_BASE, GIC_SIZE >> PAGE_BITS, PG_GLOBAL|PG_RW|PG_DEVICE);
        if (BUILTIN_EXPECT(ret, 0))
                goto oom;

	LOG_INFO("Map gicd 0x%zx at 0x%zx\n", GICD_BASE, gicd_base);
	LOG_INFO("Map gicc 0x%zx at 0x%zx\n", GICC_BASE, gicc_base);

	gicc_disable();
	gicd_disable();

	nr_irqs = ((gicd_read(GICD_TYPER) & 0x1f) + 1) * 32;
	LOG_INFO("Number of supported interrupts %u\n", nr_irqs);

	gicd_write(GICD_ICENABLER, 0xffff0000);
	gicd_write(GICD_ISENABLER, 0x0000ffff);
	gicd_write(GICD_ICPENDR, 0xffffffff);
	gicd_write(GICD_IGROUPR, 0);

	for (uint32_t i = 0; i < 32 / 4; i++) {
		gicd_write(GICD_IPRIORITYR + i * 4, 0x80808080);
	}

	for (uint32_t i = 32/16; i < nr_irqs / 16; i++) {
		gicd_write(GICD_NSACR + i * 4, 0xffffffff);
	}

	for (uint32_t i = 32/32; i < nr_irqs / 32; i++) {
		gicd_write(GICD_ICENABLER + i * 4, 0xffffffff);
		gicd_write(GICD_ICPENDR + i * 4, 0xffffffff);
		gicd_write(GICD_IGROUPR + i * 4, 0);
	}

	for (uint32_t i = 32/4; i < nr_irqs / 4; i++) {
		gicd_write(GICD_ITARGETSR + i * 4, 0);
		gicd_write(GICD_IPRIORITYR + i * 4, 0x80808080);
	}

	gicd_enable();

	gicc_set_priority(0xF0);
	gicc_enable();

	unmask_interrupt(RESCHED_INT);

	return 0;

oom:
	LOG_ERROR("Failed to intialize interrupt controller\n");

	return ret;
}

static void do_syscall(struct state *s) {
	//LOG_INFO("Handle syscall %zd\n", s->x8);

	switch(s->x8) {
#ifndef DISABLE_SYS_READ
		case __LNR_read:
			/* read */
			s->x0 = sys_read(s->x0, (char *)s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_READ */

#ifndef DISABLE_SYS_WRITE
		case __LNR_write:
			/* write */
			s->x0 = sys_write(s->x0, (char *)s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_WRITE */

#ifndef DISABLE_SYS_OPEN
		case __LNR_open:
			/* open */
			s->x0 = sys_open((const char *)s->x0, s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_OPEN */

#ifndef DISABLE_SYS_CLOSE
		case __LNR_close:
			/* close */
			s->x0 = sys_close(s->x0);
			break;
#endif /* DISABLE_SYS_CLOSE */

#if 0
#ifndef DISABLE_SYS_STAT
		case __LNR_stat:
			/* stat */
			s->x0 = sys_stat((const char *)s->x0, (struct stat *)s->x1);
			break;
#endif /* DISABLE_SYS_STAT */
#endif

#ifndef DISABLE_SYS_FSTAT
		case __LNR_fstat:
			/* fstat */
			s->x0 = sys_fstat(s->x0, (struct stat *)s->x1);
			break;
#endif /* DISABLE_SYS_FSTAT */

#ifndef DISABLE_SYS_LSTAT
		case __LNR_lstat:
			/* lstat */
			s->x0 = sys_lstat((const char *)s->x0, (struct stat *)s->x1);
			break;
#endif /* DISABLE_SYS_LSTAT */

#ifndef DISABLE_SYS_LSEEK
		case __LNR_lseek:
			/* lseek */
			s->x0 = sys_lseek(s->x0, s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_LSEEK */

#ifndef DISABLE_SYS_MMAP /* encompasses mmap and munmap */
		case __LNR_mmap:
			/* mmap */
			s->x0 = sys_mmap(s->x0, s->x1, s->x2, s->x3, s->x5,
					s->x4);
			break;
#endif /* DISABLE_SYS_MMAP */

#ifndef DISABLE_SYS_MPROTECT
		case __LNR_mprotect:
			/* mprotect */
			s->x0 = sys_mprotect(s->x1, s->x0, s->x2);
			break;
#endif /* DISABLE_SYS_MPROTECT */

#ifndef DISABLE_SYS_MUNMAP
		case __LNR_munmap:
			/* munmap */
			s->x0 = sys_munmap(s->x0, s->x1);
			break;
#endif /* DISABLE_SYS_MUNMAP */

#ifndef DISABLE_SYS_BRK
		case __LNR_brk:
			/* brk */
			s->x0 = sys_brk(s->x0);
			break;
#endif /* DISABLE_SYS_BRK */

#ifndef DISABLE_SYS_RT_SIGACTION
		case __LNR_rt_sigaction:
			/* rt_sigaction */
			s->x0 = sys_rt_sigaction(s->x0,
					(struct sigaction *)s->x1,
					(struct sigaction *)s->x2);
			break;
#endif /* DISABLE_SYS_RT_SIGACTION */

#ifndef DISABLE_SYS_RT_SIGPROCMASK
			case __LNR_rt_sigprocmask:
				/* rt_sigprocmask */
				/* FIXME */
				s->x0 = 0;
				break;
#endif /* DISABLE_SYS_RT_SIGPROCMASK */

#ifndef DISABLE_SYS_IOCTL
		case __LNR_ioctl:
			/* ioctl */
			s->x0 = sys_ioctl(s->x0, s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_IOCTL */

#ifndef DISABLE_SYS_PREAD64
		case __LNR_pread64:
			/* pread64 */
			s->x0 = sys_pread64(s->x0, (void *)s->x1, s->x2, s->x3);
			break;
#endif

#ifndef DISABLE_SYS_PWRITE64
		case __LNR_pwrite64:
			/* pwrite64 */
			s->x0 = sys_pwrite64(s->x0, (void *)s->x1, s->x2, s->x3);
			break;
#endif

#ifndef DISABLE_SYS_READV
		case __LNR_readv:
			/* readv */
			s->x0 = sys_readv(s->x0, (const struct iovec *)s->x1,
					s->x2);
			break;
#endif /* DISABLE_SYS_READV */

#ifndef DISABLE_SYS_WRITEV
		case __LNR_writev:
			/* writev */
			s->x0 = sys_writev(s->x0, (const struct iovec *)s->x1,
					s->x2);
			break;
#endif /* DISABLE_SYS_WRITEV */

#ifndef DISABLE_SYS_ACCESS
		case __LNR_access:
			/* access */
			s->x0 = sys_access((const char *)s->x0, s->x1);
			break;
#endif /* DISABLE_SYS_ACCESS */

#ifndef DISABLE_SYS_SELECT
		case __LNR_select:
			/* select */
			s->x0 = sys_select(s->x0, (void *)s->x1, (void *)s->x2,
					(void *)s->x3, (void *)s->x5);
			break;
#endif

#ifndef DISABLE_SYS_SCHED_YIELD
		case __LNR_sched_yield:
			/* sched_yield */
			s->x0 = sys_sched_yield();
			break;
#endif /* DISABLE_SYS_SCHED_YIELD */

#ifndef DISABLE_SYS_MREMAP
		case __LNR_mremap:
			/* mremap */
			s->x0 = sys_mremap(s->x0, s->x1, s->x2, s->x3, s->x5);
			break;
#endif

#if 0
#ifndef DISABLE_SYS_MINCORE
		case __LNR_minicore:
			/* mincore */
			s->x0 = sys_mincore(s->x0, s->x1, (unsigned char *)s->x2);
			break;
#endif
#endif

#ifndef DISABLE_SYS_MADVISE
		case __LNR_madvise:
			/* madvise */
			s->x0 = sys_madvise(s->x0, s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_MADVISE */

#ifndef DISABLE_SYS_NANOSLEEP
		case __LNR_nanosleep:
			/* nanosleep */
			s->x0 = sys_nanosleep((struct timespec *)s->x0,
					(struct timespec *)s->x1);
#endif /* DISABLE_SYS_NANOSLEEP */

#ifndef DISABLE_SYS_GETPID
		case __LNR_getpid:
			/* getpid */
			s->x0 = sys_getpid();
			break;
#endif /* DISABLE_SYS_GETPID */

#ifndef DISABLE_SYS_SENDFILE
		case __LNR_sendfile:
			/* sendfile */
			s->x0 = sys_sendfile(s->x0, s->x1, (void *)s->x2, s->x3);
			break;
#endif

#ifndef DISABLE_SYS_SOCKET
		case __LNR_socket:
			/* socket */
			s->x0 = sys_socket(s->x0, s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_SOCKET */

#ifndef NO_NET
#ifndef DISABLE_SYS_CONNECT
		case __LNR_connect:
			/* connect */
			s->x0 = sys_connect(s->x0, (const struct sockaddr*) s->x1, s->x2);
			break;
#endif
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_ACCEPT
		case __LNR_accept:
			/* accept */
			s->x0 = sys_accept(s->x0, (struct sockaddr *) s->x1, (unsigned int *)s->x2);
			break;
#endif /* DISABLE_SYS_ACCEPT */

#ifndef DISABLE_SYS_SENDTO
		case __LNR_sendto:
			/* sendto */
			s->x0 = sys_sendto(s->x0, (void *)s->x1, s->x2, s->x3,
					(const struct sockaddr *)s->x5, s->x4);
			break;
#endif

#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_RECVFROM
		case __LNR_recvfrom:
			/* recvfrom */
			s->x0 = sys_recvfrom(s->x0, (void *)s->x1, s->x2, s->x3, (struct sockaddr *)s->x5, (unsigned int *)s->x4);
			break;
#endif /* DISABLE_SYS_RECVFROM */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_SHUTDOWN
		case __LNR_shutdown:
			/* shutdown */
			s->x0 = sys_shutdown(s->x0, s->x1);
			break;
#endif /* DISABLE_SYS_SHUTDOWN */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_BIND
		case __LNR_bind:
			/* bind */
			s->x0 = sys_bind(s->x0, (struct sockaddr *)s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_BIND */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_LISTEN
		case __LNR_listen:
			/* listen */
			s->x0 = sys_listen(s->x0, s->x1);
			break;
#endif
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_GETSOCKNAME
		case __LNR_getsockname:
			/* getsockname */
			s->x0 = sys_getsockname(s->x0, (struct sockaddr *)s->x1, (unsigned int *)s->x2);
			break;
#endif

#ifndef DISABLE_SYS_GETPEERNAME
		case __LNR_getpeername:
			/* getpeername */
			s->x0 = sys_getpeername(s->x0, (void *)s->x1, (void *)s->x2);
			break;
#endif

#endif /* NO_NET */

#ifndef DISABLE_SYS_CLONE
		case __LNR_clone:
			/* clone */
			s->x0 = sys_clone(s->x0, (void *)s->x1, (int *)s->x2, (int *)s->x3, (void *)s->x5, (void *)s->x4);
			break;
#endif /* DISABLE_SYS_CLONE */

#ifndef DISABLE_SYS_EXIT
		case __LNR_exit:
			/* exit */
			sys_exit(s->x0);
			LOG_ERROR("Should not reach here after exit ... \n");
			break;
#endif /* DISABLE_SYS_EXIT */

#ifndef DISABLE_SYS_SETSOCKOPT
		case __LNR_setsockopt:
			/* setsockopt */
			s->x0 = sys_setsockopt(s->x0, s->x1, s->x2, (char *)s->x3, s->x5);
			break;
#endif /* DISABLE_SYS_SETSOCKOPT */

#ifndef DISABLE_SYS_UNAME
		case __LNR_uname:
			/* uname */
			s->x0 = sys_uname((void *)s->x0);
			break;
#endif /* DISABLE_SYS_UNAME */

#ifndef DISABLE_SYS_FCNTL
		case __LNR_fcntl:
			/* fcntl */
			s->x0 = sys_fcntl(s->x0, s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_FCNTL */

#ifndef DISABLE_SYS_FSYNC
		case __LNR_fsync:
			/* fsync */
			s->x0 = sys_fsync(s->x0);
			break;
#endif

#ifndef DISABLE_SYS_FDATASYNC
		case __LNR_fdatasync:
			/* fdatasync */
			s->x0 = sys_fdatasync(s->x0);
			break;
#endif

#ifndef DISABLE_SYS_GETDENTS
		case __LNR_getdents:
			/* getdents */
			s->x0 = sys_getdents(s->x0, (void *)s->x1, s->x2);
			break;
#endif

#ifndef DISABLE_SYS_GETCWD
		case __LNR_getcwd:
			/* getcwd */
			s->x0 = sys_getcwd((char *)s->x0, s->x1);
			break;
#endif /* DISABLE_SYS_GETCWD */

#ifndef DISABLE_SYS_CHDIR
		case __LNR_chdir:
			s->x0 = sys_chdir((const char *)s->x0);
			break;
#endif

#ifndef DISABLE_SYS_MKDIR
		case __LNR_mkdir:
			/* mkdir */
			s->x0 = sys_mkdir((const char *)s->x0, s->x1);
			break;
#endif /* DISABLE_SYS_MKDIR */

#ifndef DISABLE_SYS_RMDIR
		case __LNR_rmdir:
			/* rmdir */
			s->x0 = sys_rmdir((const char *)s->x0);
			break;
#endif /* DISABLE_SYS_RMDIR */

#ifndef DISABLE_SYS_CREAT
		case __LNR_creat:
			/* creat */
			s->x0 = sys_creat((const char *)s->x0, s->x1);
			break;
#endif

#ifndef DISABLE_SYS_UNLINK
		case __LNR_unlink:
			/* unlink */
			s->x0 = sys_unlink((const char *)s->x0);
			break;
#endif /* DISABLE_SYS_UNLINK */

#ifndef DISABLE_SYS_READLINK
		case __LNR_readlink:
			/* readlink */
			s->x0 = sys_readlink((char *)s->x0, (char *)s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_READLINK */

#if 0
#ifndef DISABLE_SYS_UMASK
		case __LNR_unmask:
			/* umask */
			s->x0 = sys_umask(s->x0);
			break;
#endif
#endif

#ifndef DISABLE_SYS_GETTIMEOFDAY
		case __LNR_gettimeofday:
			/* gettimeofday */
			s->x0 = sys_gettimeofday((struct timeval *)s->x0,
					(struct timezone *)s->x1);
			break;
#endif /* DISABLE_SYS_GETTIMEOFDAY */

#ifndef DISABLE_SYS_GETRLIMIT
		case __LNR_getrlimit:
			/* getrlimit */
			s->x0 = sys_getrlimit(s->x0, (struct rlimit *)s->x1);
			break;
#endif /* DISABLE_SYS_GETRLIMIT */

#ifndef DISABLE_SYS_SYSINFO
		case __LNR_sysinfo:
			/* sysinfo */
			s->x0 = sys_sysinfo((void *)s->x0);
			break;
#endif

#ifndef DISABLE_SYS_GETUID
		case __LNR_getuid:
			/* getuid */
			s->x0 = sys_getuid();
			break;
#endif /* DISABLE_SYS_GETUID */

#ifndef DISABLE_SYS_GETGID
		case __LNR_getgid:
			s->x0 = sys_getgid();
			break;
#endif /* DISABLE_SYS_GETGID */

#ifndef DISABLE_SYS_GETEUID
		case __LNR_geteuid:
			/* geteuid */
			s->x0 = sys_geteuid();
			break;
#endif /* DISABLE_SYS_GETEUID */

#ifndef DISABLE_SYS_GETEGID
		case __LNR_getegid:
			s->x0 = sys_getegid();
			break;
#endif /* DISABLE_SYS_GETEGID */

#ifndef DISABLE_SYS_GETPPID
		case __LNR_getppid:
			s->x0 = (long)0;
			s->x0 = sys_getppid();
			break;
#endif /* DISABLE_SYS_GETPPID */

#ifndef DISABLE_SYS_SETSID
		case __LNR_setsid:
			s->x0 = sys_setsid();
			break;
#endif

#ifndef DISABLE_SYS_SIGALTSTACK
		case __LNR_sigaltstack:
			s->x0 = sys_sigaltstack((const stack_t *)s->x0, (stack_t *)s->x1);
			break;
#endif

#ifndef DISABLE_SYS_GETPRIORITY
		case __LNR_getpriority:
			/* getpriority */
			s->x0 = sys_getpriority(s->x0, s->x1);
			break;
#endif /* DISABLE_SYS_GETPRIORITY */

#ifndef DISABLE_SYS_SETPRIORITY
		case __LNR_setpriority:
			/* setpriority */
			s->x0 = sys_setpriority(s->x0, s->x1, s->x2);
			break;
#endif

#if 0
#ifndef DISABLE_SYS_ARCH_PRCTL
		case 158:
			/* arch_prctl */
			s->x0 = sys_arch_prctl(s->x0, (unsigned long *)s->x1, (void *)s->x2);
			break;
#endif /* DISABLE_SYS_ARCH_PRCTL */
#endif

#ifndef DISABLE_SYS_SETRLIMIT
		case __LNR_setrlimit:
			/* setrlimit */
			s->x0 = sys_setrlimit(s->x0, (void *)s->x1);
			break;
#endif

#ifndef DISABLE_SYS_SYNC
		case __LNR_sync:
			/* sync */
			s->x0 = sys_sync();
			break;
#endif

#ifndef DISABLE_SYS_SETHOSTNAME
		case __LNR_sethostname:
			/* sethostname */
			s->x0 = sys_sethostname((char *)s->x0, s->x1);
#endif

#ifndef DISABLE_SYS_GETTID
			case __LNR_gettid:
				/* gettid */
				s->x0 = sys_gettid();
				break;
#endif /* DISABLE_SYS_GETTID */

#ifndef DISABLE_SYS_TKILL
			case __LNR_tkill:
				/* tkill */
				s->x0 = sys_tkill(s->x0, s->x1);
				break;
#endif /* DISABLE_SYS_TKILL */

#ifndef DISABLE_SYS_TIME
			case __LNR_time:
				/* time */
				s->x0 = sys_time((long int *)s->x0);
				break;
#endif /* DISABLE_SYS_TIME */

#ifndef DISABLE_SYS_FUTEX
			case __LNR_futex:
				/* futex */
				s->x0 = sys_futex((int *)s->x0, s->x1, s->x2, (const struct timespec *)s->x3, (int *)s->x4, s->x5);
				break;
#endif /* DISABLE_SYS_FUXTEX */

#ifndef DISABLE_SYS_SCHED_SETAFFINITY
			case __LNR_sched_setaffinity:
				s->x0 = sys_sched_setaffinity(s->x0, s->x1, (long unsigned int *)s->x2);
				break;
#endif /* DISABLE_SYS_SCHED_SETAFFINITY */

#ifndef DISABLE_SYS_SCHED_GETAFFINITY
			case __LNR_sched_getaffinity:
				s->x0 = sys_sched_getaffinity(s->x0, s->x1, (long unsigned int *)s->x2);
				break;
#endif /* DISABLE_SYS_SCHED_GETAFFINITY */

#ifndef DISABLE_SYS_GETDENTS64
			case __LNR_getdents64:
				/* getdents64 */
				s->x0 = sys_getdents64(s->x0, (void *)s->x1, s->x2);
				break;
#endif

#ifndef DISABLE_SYS_SET_TID_ADDRESS
		case __LNR_set_tid_address:
			/* set_tid_address */
			s->x0 = sys_set_tid_address((int *)s->x0);
			break;
#endif /* DISABLE_SYS_SET_TID_ADDRESS */

#ifndef DISABLE_SYS_CLOCK_GETTIME
		case __LNR_clock_gettime:
			/* clock_gettime */
			s->x0 = sys_clock_gettime(s->x0, (struct timespec *)s->x1);
			break;
#endif /* DISABLE_SYS_CLOCK_GETTIME */

#ifndef DISABLE_SYS_CLOCK_GETRES
		case __LNR_clock_getres:
			/* clock_getres */
			s->x0 = sys_clock_getres(s->x0, (struct timespec *)s->x1);
			break;
#endif

#ifndef DISABLE_SYS_TGKILL
		case __LNR_tgkill:
			/* tgkill */
			s->x0 = sys_tgkill(s->x0, s->x1, s->x2);
			break;
#endif /* DISABLE_SYS_TGKILL */

#ifndef DISABLE_SYS_OPENAT
		case __LNR_openat:
			s->x0 = sys_openat(s->x0, (const char *)s->x1, s->x2, s->x3);
			break;
#endif /* DISABLE_SYS_OPENAT */

#ifndef DISABLE_SYS_EXIT_GROUP
		case __LNR_exit_group:
			/* exit_group */
			sys_exit_group(s->x0);
			LOG_ERROR("Should not reach here after exit_group ... \n");
			break;
#endif /* DISABLE_SYS_EXIT_GROUP */

#ifndef DISABLE_SYS_SET_ROBUST_LIST
		case __LNR_set_robust_list:
			/* set_robust_list */
			s->x0 = sys_set_robust_list((void *)s->x0, s->x1);
			break;
#endif /* DISABLE_SYS_SET_ROBUST_LIST */

#ifndef DISABLE_SYS_GET_ROBUST_LIST
		case __LNR_get_robust_list:
			/* get_robust_list */
			s->x0 = sys_get_robust_list(s->x0, (void *)s->x1, (size_t *)s->x2);
			break;
#endif /* DISABLE_SYS_GET_ROBUST_LIST */

#ifndef DISABLE_SYS_PRLIMIT64
		case __LNR_prlimit64:
			/* prlimit64 */
			s->x0 = sys_prlimit64(s->x0, s->x1, (struct rlimit *)s->x2,
					(struct rlimit *)s->x3);
			break;
#endif

#ifndef DISABLE_SYS_SYNCFS
		case __LNR_syncfs:
			/* syncfs */
			s->x0 = sys_syncfs(s->x0);
			break;
#endif

	default:
		LOG_ERROR("Unable to handle syscall %zd", s->x8);
		sys_exit(-EFAULT);
	}
}

void do_sync(struct state *regs)
{
	uint32_t iar = gicc_read(GICC_IAR);
	uint32_t esr = read_esr();
	uint32_t ec = esr >> 26;
	uint32_t iss = esr & 0xFFFFFF;
	uint64_t pc = get_elr();

        /* data abort from lower or current level */
	if ((ec == 0b100100) || (ec == 0b100101)) {
		/* check if value in far_el1 is valid */
		if (!(iss & (1 << 10))) {
			/* read far_el1 register, which holds the faulting virtual address */
			uint64_t far = read_far();

			if (page_fault_handler(far, pc) == 0)
				return;

			LOG_ERROR("Unable to handle page fault at 0x%llx\n", far);
			LOG_ERROR("Exception return address 0x%llx\n", get_elr());
			LOG_ERROR("Thread ID register 0x%llx\n", get_tpidr());
			LOG_ERROR("Table Base Register 0x%llx\n", get_ttbr0());
			LOG_ERROR("Exception Syndrome Register 0x%lx\n", esr);

			// send EOI
			gicc_write(GICC_EOIR, iar);
			//do_abort();
			sys_exit(-EFAULT);
		} else {
			LOG_ERROR("Unknown exception\n");
		}
	} else if (ec == 0x15) {
		//LOG_INFO("Receive system call, PC=0x%x\n", pc);
		do_syscall(regs);
		return;
	} else if (ec == 0x3c) {
		LOG_ERROR("Trap to debugger, PC=0x%x\n", pc);
	} else {
		LOG_ERROR("Unsupported exception class: 0x%x, PC=0x%x\n", ec, pc);
	}

	sys_exit(-EFAULT);

}

size_t** do_fiq(void *regs)
{
	size_t** ret = NULL;
	uint32_t iar = gicc_read(GICC_IAR);
	uint32_t vector = iar & 0x3ff;

	//LOG_INFO("Receive fiq %d\n", vector);

	if (vector < MAX_HANDLERS && irq_routines[vector]) {
		(irq_routines[vector])(regs);
	} else if (vector != RESCHED_INT) {
		LOG_INFO("Unable to handle fiq %d\n", vector);
	}

	// Check if timers have expired that would unblock tasks
	check_workqueues_in_irqhandler(vector);

	if ((vector == INT_PPI_NSPHYS_TIMER) || (vector == RESCHED_INT)) {
		// a timer interrupt may have caused unblocking of tasks
		ret = scheduler();
	} else if (get_highest_priority() > per_core(current_task)->prio) {
		// there's a ready task with higher priority
		ret = scheduler();
	}

	gicc_write(GICC_EOIR, iar);

	return ret;
}

size_t** do_irq(void *regs)
{
	size_t** ret = NULL;
	uint32_t iar = gicc_read(GICC_IAR);
	uint32_t vector = iar & 0x3ff;

	LOG_INFO("Receive interrupt %d\n", vector);

	// Check if timers have expired that would unblock tasks
	check_workqueues_in_irqhandler(vector);

	if (get_highest_priority() > per_core(current_task)->prio) {
		// there's a ready task with higher priority
		ret = scheduler();
	}

	gicc_write(GICC_EOIR, iar);

	return ret;
}

void do_error(void *regs)
{
	LOG_ERROR("Receive error interrupt\n");

	while (1) {
		HALT;
	}
}

void do_bad_mode(void *regs, int reason)
{
	LOG_ERROR("Receive unhandled exception: %d\n", reason);

	while (1) {
		HALT;
	}
}

void reschedule(void)
{
	// (2 << 24) = Forward the interrupt only to the CPU interface of the PE that requested the interrupt
	gicd_write(GICD_SGIR, (2 << 24) | RESCHED_INT);
}
