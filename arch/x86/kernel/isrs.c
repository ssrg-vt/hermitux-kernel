/*
 * Copyright (c) 2010, Stefan Lankes, RWTH Aachen University
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

/**
 * @author Stefan Lankes
 * @file arch/x86/kernel/isrs.c
 * @brief Installation of interrupt service routines and definition of fault handler.
 *
 * This file contains prototypes for the first 32 entries of the IDT,
 * an ISR installer procedure and a fault handler.\n
 */

#include <hermit/stdio.h>
#include <hermit/tasks.h>
#include <hermit/errno.h>
#include <hermit/logging.h>
#include <asm/irqflags.h>
#include <asm/isrs.h>
#include <asm/irq.h>
#include <asm/idt.h>
#include <asm/apic.h>

char *syscalls_names[250];

#define SYSCALL_INT_NO 6
#define NO_SYSCALLS 328

static void dummy_handler(void)
{
	size_t rax;

	asm volatile ("movq %%rax, %0" : "=r"(rax));

	LOG_INFO("Caught unhandled syscall %zd\n", rax);
	sys_exit(-EFAULT);
}

size_t sys_handlers[NO_SYSCALLS] = { [0 ... NO_SYSCALLS-1] = (size_t) dummy_handler };

/*
 * These are function prototypes for all of the exception
 * handlers: The first 32 entries in the IDT are reserved
 * by Intel and are designed to service exceptions!
 */
extern void isr0(void);
extern void isr1(void);
extern void isr2(void);
extern void isr3(void);
extern void isr4(void);
extern void isr5(void);
extern void isr6(void);
extern void isr7(void);
extern void isr8(void);
extern void isr9(void);
extern void isr10(void);
extern void isr11(void);
extern void isr12(void);
extern void isr13(void);
extern void isr14(void);
extern void isr15(void);
extern void isr16(void);
extern void isr17(void);
extern void isr18(void);
extern void isr19(void);
extern void isr20(void);
extern void isr21(void);
extern void isr22(void);
extern void isr23(void);
extern void isr24(void);
extern void isr25(void);
extern void isr26(void);
extern void isr27(void);
extern void isr28(void);
extern void isr29(void);
extern void isr30(void);
extern void isr31(void);

static void arch_fault_handler(struct state *s);
static void arch_fpu_handler(struct state *s);
extern void fpu_handler(void);
static void static_syscall_handler(struct state *s);

int connect(int s, size_t name, size_t namelen);
int listen(int s, int backlog);
int recvfrom(int s, size_t mem, size_t len, int flags, size_t from, size_t fromlen);
int send(int s, size_t dataptr, size_t size, int flags);
int accept(int s, size_t addr, size_t addrlen);
int bind(int s, size_t name, size_t namelen);
int getsockopt(int s, int level, int optname, size_t optval, size_t optlen);
int setsockopt(int s, int level, int optname, size_t optval, size_t optlen);
int shutdown(int socket, int how);
int getsockname(int s, size_t ame, size_t namelen);

size_t sys_set_tid_address(size_t tid)
{
	/* TODO */
	return tid;
}

size_t sys_munmap(void)
{
	/* TODO */
	return -ENOSYS;
}

size_t sys_t_sigprocmask(void)
{
	return 0;
}

int sys_readlink(const char* arg)
{
	/* readlink */
	kprintf("readlink path %s\n", arg);
	return -1;
}

static void init_syscalls_names() {
	syscalls_names[0] = "read";
	syscalls_names[1] = "write";
	syscalls_names[2] = "open";
	syscalls_names[3] = "close";
	syscalls_names[12] = "brk";
	syscalls_names[16] = "ioctl";
	syscalls_names[20] = "writev";
	syscalls_names[63] = "uname";
	syscalls_names[158] = "arch_prctl";
	syscalls_names[218] = "set_tid_address";
	syscalls_names[228] = "clock_gettime";
	syscalls_names[231] = "exit_group";
}

/*
 * This is a very repetitive function... it's not hard, it's
 * just annoying. As you can see, we set the first 32 entries
 * in the IDT to the first 32 ISRs. We can't use a for loop
 * for this, because there is no way to get the function names
 * that correspond to that given entry. We set the access
 * flags to 0x8E. This means that the entry is present, is
 * running in ring 0 (kernel level), and has the lower 5 bits
 * set to the required '14', which is represented by 'E' in
 * hex.
 */
void isrs_install(void)
{
	int i;

	/*
	 * "User-level" doesn't protect the red zone. Consequently we
	 * protect the common stack by the usage of IST number 1.
	 */
	idt_set_gate(0, (size_t)isr0, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(1, (size_t)isr1, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	// NMI Exception gets its own stack (ist2)
	idt_set_gate(2, (size_t)isr2, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 2);
	idt_set_gate(3, (size_t)isr3, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(4, (size_t)isr4, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(5, (size_t)isr5, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(6, (size_t)isr6, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(7, (size_t)isr7, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	// Double Fault Exception gets its own stack (ist3)
	idt_set_gate(8, (size_t)isr8, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 3);
	idt_set_gate(9, (size_t)isr9, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(10, (size_t)isr10, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(11, (size_t)isr11, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(12, (size_t)isr12, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(13, (size_t)isr13, KERNEL_CODE_SELECTOR,
		 IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(14, (size_t)isr14, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(15, (size_t)isr15, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(16, (size_t)isr16, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(17, (size_t)isr17, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	// Machine Check Exception gets its own stack (ist4)
	idt_set_gate(18, (size_t)isr18, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 4);
	idt_set_gate(19, (size_t)isr19, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(20, (size_t)isr20, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(21, (size_t)isr21, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(22, (size_t)isr22, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(23, (size_t)isr23, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(24, (size_t)isr24, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(25, (size_t)isr25, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(26, (size_t)isr26, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(27, (size_t)isr27, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(28, (size_t)isr28, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(29, (size_t)isr29, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(30, (size_t)isr30, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);
	idt_set_gate(31, (size_t)isr31, KERNEL_CODE_SELECTOR,
		IDT_FLAG_PRESENT|IDT_FLAG_RING0|IDT_FLAG_32BIT|IDT_FLAG_INTTRAP, 1);


	// install the default handler
	for(i=0; i<32; i++)
		irq_install_handler(i, arch_fault_handler);

	// For static syscalls
	irq_uninstall_handler(SYSCALL_INT_NO);
	irq_install_handler(SYSCALL_INT_NO, static_syscall_handler);

	init_syscalls_names();

	// init syscall handlers

#ifndef DISABLE_SYS_READ
	/* read */
	sys_handlers[0] = (size_t) sys_read;
#endif /* DISABLE_SYS_READ */

#ifndef DISABLE_SYS_WRITE
	/* write */
	sys_handlers[1] = (size_t) sys_write;
#endif /* DISABLE_SYS_WRITE */

#ifndef DISABLE_SYS_OPEN
	/* open */
	sys_handlers[2] = (size_t) sys_open;
#endif /* DISABLE_SYS_OPEN */

#ifndef DISABLE_SYS_CLOSE
	/* close */
	sys_handlers[3] = (size_t) sys_close;
#endif /* DISABLE_SYS_CLOSE */

#ifndef DISABLE_SYS_STAT
	/* stat */
	sys_handlers[4] = (size_t)sys_stat;
#endif /* DISABLE_SYS_STAT */

#ifndef DISABLE_SYS_FSTAT
	/* fstat */
	sys_handlers[5] = (size_t) sys_fstat;
#endif /* DISABLE_SYS_FSTAT */

#ifndef DISABLE_SYS_LSTAT
	/* lstat */
	sys_handlers[6] = (size_t) sys_lstat;
#endif /* DISABLE_SYS_LSTAT */

#ifndef DISABLE_SYS_LSEEK
	/* lseek */
	sys_handlers[8] = (size_t) sys_lseek;
#endif /* DISABLE_SYS_LSEEK */

#ifndef DISABLE_SYS_MMAP /* encompasses mmap and munmap */
	/* mmap */
	sys_handlers[9] = (size_t) sys_mmap;

	/* munmap */
	sys_handlers[11] = (size_t) sys_munmap;
#endif /* DISABLE_SYS_MMAP */

#ifndef DISABLE_SYS_BRK
	/* brk */
	sys_handlers[12] = (size_t) sys_brk;
#endif /* DISABLE_SYS_BRK */

#ifndef DISABLE_SYS_RT_SIGACTION
	/* rt_sigaction */
	sys_handlers[13] = (size_t) sys_rt_sigaction;
#endif /* DISABLE_SYS_RT_SIGACTION */

#ifndef DISABLE_SYS_RT_SIGPROCMASK
	/* rt_sigprocmask */
	sys_handlers[14] = sys_t_sigprocmask;
#endif

#ifndef DISABLE_SYS_IOCTL
	/* ioctl */
	sys_handlers[16] = (size_t) sys_ioctl;
#endif /* DISABLE_SYS_IOCTL */

#ifndef DISABLE_SYS_READV
	/* readv */
	sys_handlers[19] = (size_t) sys_readv;
#endif /* DISABLE_SYS_READV */

#ifndef DISABLE_SYS_WRITEV
	/* writev */
	sys_handlers[20] = (size_t) sys_writev;
#endif /* DISABLE_SYS_WRITEV */

#ifndef DISABLE_SYS_MADVISE
	/* madvise */
	sys_handlers[28] = (size_t) sys_madvise;
#endif /* DISABLE_SYS_MADVISE */

#ifndef DISABLE_SYS_NANOSLEEP
	/* nanosleep */
	sys_handlers[35] = (size_t) sys_nanosleep;
#endif /* DISABLE_SYS_NANOSLEEP */

#ifndef DISABLE_SYS_GETPID
	/* getpid */
	sys_handlers[39] = (size_t) sys_getpid;
#endif /* DISABLE_SYS_GETPID */

#ifndef DISABLE_SYS_SOCKET
	/* socket */
	sys_handlers[41] = (size_t) sys_socket;
#endif /* DISABLE_SYS_SOCKET */

#ifndef NO_NET
#ifndef DISABLE_SYS_CONNECT
	/* connect */
	sys_handlers[42] = (size_t) connect;
#endif
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_ACCEPT
	/* accept */
	sys_handlers[43] = (size_t) accept;
#endif /* DISABLE_SYS_ACCEPT */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_RECVFROM
	/* recvfrom */
	sys_handlers[45] = (size_t) recvfrom;
#endif /* DISABLE_SYS_RECVFROM */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_SHUTDOWN
	/* shutdown */
	sys_handlers[48] = (size_t) shutdown;
#endif /* DISABLE_SYS_SHUTDOWN */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_BIND
	/* bind */
	sys_handlers[49] = (size_t)sys_bind;
#endif /* DISABLE_SYS_BIND */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_LISTEN
	/* lsiten */
	sys_handlers[50] = (size_t) listen;
#endif
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_GETSOCKNAME
	/* getsockname */
	sys_handlers[51] = (size_t) getsockname;
#endif
#endif /* NO_NET */

#ifndef DISABLE_SYS_SETSOCKOPT
	/* setsockopt */
	sys_handlers[54] = (size_t) sys_setsockopt;
#endif /* DISABLE_SYS_SETSOCKOPT */

#ifndef DISABLE_SYS_EXIT
	/* exit */
	sys_handlers[60] = (size_t) sys_exit;
#endif /* DISABLE_SYS_EXIT */

#ifndef DISABLE_SYS_UNAME
	/* uname */
	sys_handlers[63] = (size_t) sys_uname;
#endif /* DISABLE_SYS_UNAME */

#ifndef DISABLE_SYS_FCNTL
	/* fcntl */
	sys_handlers[72] = (size_t) sys_fcntl;
#endif /* DISABLE_SYS_FCNTL */

#ifndef DISABLE_SYS_GETCWD
	/*getcwd */
	sys_handlers[79] = (size_t) sys_getcwd;
#endif /* DISABLE_SYS_GETCWD */

#ifndef DISABLE_SYS_MKDIR
	/* mkdir */
	sys_handlers[83] = (size_t) sys_mkdir;
#endif /* DISABLE_SYS_MKDIR */

#ifndef DISABLE_SYS_RMDIR
	/* rmdir */
	sys_handlers[84] = (size_t) sys_rmdir;
#endif /* DISABLE_SYS_RMDIR */

#ifndef DISABLE_SYS_UNLINK
	/* unlink */
	sys_handlers[87] = (size_t) sys_unlink;
#endif /* DISABLE_SYS_UNLINK */

	/* readlink */
	sys_handlers[89] = (size_t) sys_readlink;

#ifndef DISABLE_SYS_GETTIMEOFDAY
	/* gettimeofday */
	sys_handlers[96] = (size_t) sys_gettimeofday;
#endif /* DISABLE_SYS_GETTIMEOFDAY */

#ifndef DISABLE_SYS_GETPRIO
	/* getpriority */
	sys_handlers[140] = (size_t) sys_getprio;
#endif /* DISABLE_SYS_GETPRIO */

#ifndef DISABLE_SYS_ARCH_PRCTL
	/* arch_prctl */
	sys_handlers[158] = (size_t) sys_arch_prctl;
#endif /* DISABLE_SYS_ARCH_PRCTL */

#ifndef DISABLE_SYS_GETTID
	/* gettid */
	sys_handlers[186] = (size_t)sys_getpid;
#endif /* DISABLE_SYS_GETTID */

#ifndef DISABLE_SYS_TKILL
	/* tkill */
	sys_handlers[200] = (size_t) sys_kill;
#endif /* DISABLE_SYS_TKILL */

#ifndef DISABLE_SYS_SET_TID_ADDRESS
	/* set_tid_address */
	sys_handlers[218] = (size_t) sys_set_tid_address;
#endif /* DISABLE_SYS_SET_TID_ADDRESS */

#ifndef DISABLE_SYS_CLOCK_GETTIME
	/* clock_gettime */
	sys_handlers[228] = (size_t) sys_clock_gettime;
#endif /* DISABLE_SYS_CLOCK_GETTIME */

#ifndef DISABLE_SYS_EXIT_GROUP
	/* exit_group */
	/* FIXME this will probably not work in multi-threaded
	 * environments */
	sys_handlers[231] = (size_t) sys_exit;
#endif /* DISABLE_SYS_EXIT_GROUP */


	// set hanlder for fpu exceptions
	irq_uninstall_handler(7);
	irq_install_handler(7, arch_fpu_handler);
}

/** @brief Exception messages
 *
 * This is a simple string array. It contains the message that
 * corresponds to each and every exception. We get the correct
 * message by accessing it like this:
 * exception_message[interrupt_number]
 */
static const char *exception_messages[] = {
	"Division By Zero", "Debug", "Non Maskable Interrupt",
	"Breakpoint", "Into Detected Overflow", "Out of Bounds", "Invalid Opcode",
	"No Coprocessor", "Double Fault", "Coprocessor Segment Overrun", "Bad TSS",
	"Segment Not Present", "Stack Fault", "General Protection Fault", "Page Fault",
	"Unknown Interrupt", "Coprocessor Fault", "Alignment Check", "Machine Check",
	"SIMD Floating-Point", "Virtualization", "Reserved", "Reserved", "Reserved",
	"Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved",
	"Reserved", "Reserved" };

void syscall_handler(struct state *s);

static void static_syscall_handler(struct state *s)
{
	// This is actually the reversed opcode
	uint16_t *opcode = (uint16_t *)s->rip;

	/* syscall opcode = 0F05 */
	if (*opcode == 0x50F) {
		syscall_handler(s);

		/* Make sure control returns to the instruction after syscall */
                s->rip += 2;
        } else {
                arch_fault_handler(s);
        }
}

void syscall_handler(struct state *s)
{
//	LOG_INFO("Caught syscall %d (%s) %#lx:%#lx\n", s->rax, syscalls_names[s->rax]);

	switch(s->rax) {

#ifndef DISABLE_SYS_READ
		case 0:
			/* read */
			s->rax = sys_read(s->rdi, (char *)s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_READ */

#ifndef DISABLE_SYS_WRITE
		case 1:
			/* write */
			s->rax = sys_write(s->rdi, (char *)s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_WRITE */

#ifndef DISABLE_SYS_OPEN
		case 2:
			/* open */
			s->rax = sys_open((const char *)s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_OPEN */

#ifndef DISABLE_SYS_CLOSE
		case 3:
			/* close */
			s->rax = sys_close(s->rdi);
			break;
#endif /* DISABLE_SYS_CLOSE */

#ifndef DISABLE_SYS_STAT
		case 4:
			/* stat */
			s->rax = sys_stat((const char *)s->rdi, (struct stat *)s->rsi);
			break;
#endif /* DISABLE_SYS_STAT */

#ifndef DISABLE_SYS_FSTAT
		case 5:
			/* fstat */
			s->rax = sys_fstat(s->rdi, (struct stat *)s->rsi);
			break;
#endif /* DISABLE_SYS_FSTAT */

#ifndef DISABLE_SYS_LSTAT
		case 6:
			/* lstat */
			s->rax = sys_lstat((const char *)s->rdi, (struct stat *)s->rsi);
			break;
#endif /* DISABLE_SYS_LSTAT */

#ifndef DISABLE_SYS_LSEEK
		case 8:
			/* lseek */
			s->rax = sys_lseek(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_LSEEK */

#ifndef DISABLE_SYS_MMAP /* encompasses mmap and munmap */
		case 9:
			/* mmap */
			s->rax = sys_mmap(s->rdi, s->rsi, s->rdx, s->r10, s->r8,
					s->r9);
			break;

		case 11:
			/* munmap */
			/* TODO */
			s->rax = sys_munmap();
			break;
#endif /* DISABLE_SYS_MMAP */

#ifndef DISABLE_SYS_BRK
		case 12:
			/* brk */
			s->rax = sys_brk(s->rdi);
			break;
#endif /* DISABLE_SYS_BRK */

#ifndef DISABLE_SYS_RT_SIGACTION
		case 13:
			/* rt_sigaction */
			s->rax = sys_rt_sigaction(s->rdi,
					(const struct sigaction *)s->rsi,
					(struct sigaction *)s->rdx);
			break;
#endif /* DISABLE_SYS_RT_SIGACTION */

#ifndef DISABLE_SYS_RT_SIGPROCMASK
			case 14:
				/* rt_sigprocmask */
				s->rax = sys_t_sigprocmask();
				break;
#endif /* DISABLE_SYS_RT_SIGPROCMASK */

#ifndef DISABLE_SYS_IOCTL
		case 16:
			/* ioctl */
			s->rax = sys_ioctl(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_IOCTL */

#ifndef DISABLE_SYS_READV
		case 19:
			/* readv */
			s->rax = sys_readv(s->rdi, (const struct iovec *)s->rsi,
					s->rdx);
			break;
#endif /* DISABLE_SYS_READV */

#ifndef DISABLE_SYS_WRITEV
		case 20:
			/* writev */
			s->rax = sys_writev(s->rdi, (const struct iovec *)s->rsi,
					s->rdx);
			break;
#endif /* DISABLE_SYS_WRITEV */

#ifndef DISABLE_SYS_MADVISE
		case 28:
			/* madvise */
			s->rax = sys_madvise(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_MADVISE */

#ifndef DISABLE_SYS_NANOSLEEP
		case 35:
			/* nanosleep */
			s->rax = sys_nanosleep((struct timespec *)s->rdi,
					(struct timespec *)s->rsi);
#endif /* DISABLE_SYS_NANOSLEEP */

#ifndef DISABLE_SYS_GETPID
		case 39:
			/* getpid */
			s->rax = sys_getpid();
			break;
#endif /* DISABLE_SYS_GETPID */

#ifndef DISABLE_SYS_SOCKET
		case 41:
			/* socket */
			s->rax = sys_socket(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_SOCKET */

#ifndef NO_NET
#ifndef DISABLE_SYS_CONNECT
		case 42:
			/* connect */
			s->rax = connect(s->rdi, s->rsi, s->rdx);
			break;
#endif
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_ACCEPT
		case 43:
			/* accept */
			s->rax = accept(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_ACCEPT */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_RECVFROM
		case 45:
			/* recvfrom */
			s->rax = recvfrom(s->rdi, s->rsi, s->rdx, s->r10, s->r8, s->r9);
			break;
#endif /* DISABLE_SYS_RECVFROM */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_SHUTDOWN
		case 48:
			/* shutdown */
			s->rax = shutdown(s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_SHUTDOWN */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_BIND
		case 49:
			/* bind */
			s->rax = bind(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_BIND */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_LISTEN
		case 50:
			/* lsiten */
			s->rax = listen(s->rdi, s->rsi);
			break;
#endif
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_GETSOCKNAME
		case 51:
			/* getsockname */
			s->rax = getsockname(s->rdi, s->rsi, s->rdx);
			break;
#endif
#endif /* NO_NET */

#ifndef DISABLE_SYS_EXIT
		case 60:
			/* exit */
			sys_exit(s->rdi);
			LOG_ERROR("Should not reach here after exit ... \n");
			break;
#endif /* DISABLE_SYS_EXIT */

#ifndef DISABLE_SYS_SETSOCKOPT
		case 54:
			/* setsockopt */
			s->rax = sys_setsockopt(s->rdi, s->rsi, s->rdx, (char *)s->r10, s->r8);
			break;
#endif /* DISABLE_SYS_SETSOCKOPT */

#ifndef DISABLE_SYS_UNAME
		case 63:
			/* uname */
			sys_uname((void *)s->rdi);
			break;
#endif /* DISABLE_SYS_UNAME */

#ifndef DISABLE_SYS_FCNTL
		case 72:
			/* fcntl */
			s->rax = sys_fcntl(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_FCNTL */

#ifndef DISABLE_SYS_GETCWD
		case 79:
			/*getcwd */
			s->rax = sys_getcwd((char *)s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_GETCWD */

#ifndef DISABLE_SYS_MKDIR
		case 83:
			/* mkdir */
			s->rax = sys_mkdir((const char *)s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_MKDIR */

#ifndef DISABLE_SYS_RMDIR
		case 84:
			/* rmdir */
			s->rax = sys_rmdir((const char *)s->rdi);
			break;
#endif /* DISABLE_SYS_RMDIR */

#ifndef DISABLE_SYS_UNLINK
		case 87:
			/* unlink */
			s->rax = sys_unlink((const char *)s->rdi);
			break;
#endif /* DISABLE_SYS_UNLINK */

		case 89:
			/* readlink */
			s->rax = sys_readlink((const char*) s->rdi);
			break;

#ifndef DISABLE_SYS_GETTIMEOFDAY
		case 96:
			/* gettimeofday */
			s->rax = sys_gettimeofday((struct timeval *)s->rdi,
					(struct timezone *)s->rsi);
			break;
#endif /* DISABLE_SYS_GETTIMEOFDAY */

#ifndef DISABLE_SYS_GETPRIO
		case 140:
			/* getpriority */
			s->rax = sys_getprio((unsigned int *)&(s->rsi));
			break;
#endif /* DISABLE_SYS_GETPRIO */

#ifndef DISABLE_SYS_ARCH_PRCTL
		case 158:
			/* arch_prctl */
			s->rax = sys_arch_prctl(s->rdi, (unsigned long *)s->rsi);
			break;
#endif /* DISABLE_SYS_ARCH_PRCTL */

#ifndef DISABLE_SYS_GETTID
			case 186:
				/* gettid */
				s->rax = sys_getpid();
				break;
#endif /* DISABLE_SYS_GETTID */

#ifndef DISABLE_SYS_TKILL
			case 200:
				/* tkill */
				s->rax = sys_kill(s->rdi, s->rsi);
				break;
#endif /* DISABLE_SYS_TKILL */

#ifndef DISABLE_SYS_SET_TID_ADDRESS
		case 218:
			/* set_tid_address */
			s->rax = sys_set_tid_address(s->rdi);
			break;
#endif /* DISABLE_SYS_SET_TID_ADDRESS */

#ifndef DISABLE_SYS_CLOCK_GETTIME
		case 228:
			/* clock_gettime */
			s->rax = sys_clock_gettime(s->rdi, (struct timespec *)s->rsi);
			break;
#endif /* DISABLE_SYS_CLOCK_GETTIME */

#ifndef DISABLE_SYS_EXIT_GROUP
		case 231:
			/* exit_group */
			/* FIXME this will probably not work in multi-threaded
			 * environments */
			sys_exit(s->rdi);
			LOG_ERROR("Should not reach here after exit_group ... \n");
			break;
#endif /* DISABLE_SYS_EXIT_GROUP */

		default:
			LOG_ERROR("Unsuported Linux syscall: %d\n", s->rax);
			sys_exit(-EFAULT);
	}
}



/* interrupt handler to save / restore the FPU context */
static void arch_fpu_handler(struct state *s)
{
	(void) s;

	clts(); // clear the TS flag of cr0

	fpu_handler();
}


/*
 * All of our Exception handling Interrupt Service Routines will
 * point to this function. This will tell us what exception has
 * occured! Right now, we simply abort the current task.
 * All ISRs disable interrupts while they are being
 * serviced as a 'locking' mechanism to prevent an IRQ from
 * happening and messing up kernel data structures
 */
static void arch_fault_handler(struct state *s)
{
	if (s->int_no < 32)
		LOG_INFO("%s\n", exception_messages[s->int_no]);
	else
		LOG_WARNING("Unknown exception %d\n", s->int_no);

	LOG_ERROR(" Exception (%d) on core %d at %#x:%#lx, fs = %#lx, gs = %#lx, error code = %#lx, task id = %u, rflags = %#x\n",
		s->int_no, CORE_ID, s->cs, s->rip, s->fs, s->gs, s->error, per_core(current_task)->id, s->rflags);
	LOG_ERROR("rax %#lx, rbx %#lx, rcx %#lx, rdx %#lx, rbp %#lx, rsp %#lx rdi %#lx, rsi %#lx, r8 %#lx, r9 %#lx, r10 %#lx, r11 %#lx, r12 %#lx, r13 %#lx, r14 %#lx, r15 %#lx\n",
		s->rax, s->rbx, s->rcx, s->rdx, s->rbp, s->rsp, s->rdi, s->rsi, s->r8, s->r9, s->r10, s->r11, s->r12, s->r13, s->r14, s->r15);

	apic_eoi(s->int_no);
	//do_abort();
	sys_exit(-EFAULT);
}
