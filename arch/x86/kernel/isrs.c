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

#include <hermit/syscall-config.h>

#include <asm/uhyve.h>

#define SYSCALL_INT_NO 6

typedef struct {
	uint64_t rip;
	uint32_t int_no;
} __attribute__ ((packed)) uhyve_fault_t;

/* Are we running under gdb? (set by uhyve) */
extern const uint8_t tux_gdb;

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
//	LOG_INFO("Caught syscall %d (%s) %#lx:%#lx\n", s->rax);

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

#ifndef DISABLE_SYS_POLL
        case 7:
            /* poll */
            s->rax = sys_poll((void *)s->rdi, s->rsi, s->rdx);
            break;
#endif

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
#endif /* DISABLE_SYS_MMAP */

#ifndef DISABLE_SYS_MPROTECT
		case 10:
			/* mprotect */
			s->rax = sys_mprotect(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_MPROTECT */

#ifndef DISABLE_SYS_MUNMAP
		case 11:
			/* munmap */
			s->rax = sys_munmap(s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_MUNMAP */

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
					(struct sigaction *)s->rsi,
					(struct sigaction *)s->rdx);
			break;
#endif /* DISABLE_SYS_RT_SIGACTION */

#ifndef DISABLE_SYS_RT_SIGPROCMASK
			case 14:
				/* rt_sigprocmask */
				/* FIXME */
				s->rax = 0;
				break;
#endif /* DISABLE_SYS_RT_SIGPROCMASK */

#ifndef DISABLE_SYS_IOCTL
		case 16:
			/* ioctl */
			s->rax = sys_ioctl(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_IOCTL */

#ifndef DISABLE_SYS_PREAD64
		case 17:
			/* pread64 */
			s->rax = sys_pread64(s->rdi, (void *)s->rsi, s->rdx, s->r10);
			break;
#endif

#ifndef DISABLE_SYS_PWRITE64
		case 18:
			/* pwrite64 */
			s->rax = sys_pwrite64(s->rdi, (void *)s->rsi, s->rdx, s->r10);
			break;
#endif

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

#ifndef DISABLE_SYS_ACCESS
		case 21:
			/* access */
			s->rax = sys_access((const char *)s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_ACCESS */

#ifndef DISABLE_SYS_PIPE
        case 22:
            /* pipe */
            s->rax = sys_pipe((int *)s->rdi);
            break;
#endif

#ifndef DISABLE_SYS_SELECT
		case 23:
			/* select */
			s->rax = sys_select(s->rdi, (void *)s->rsi, (void *)s->rdx,
					(void *)s->r10, (void *)s->r8);
			break;
#endif

#ifndef DISABLE_SYS_SCHED_YIELD
		case 24:
			/* sched_yield */
			s->rax = sys_sched_yield();
			break;
#endif /* DISABLE_SYS_SCHED_YIELD */

#ifndef DISABLE_SYS_MREMAP
		case 25:
			/* mremap */
			s->rax = sys_mremap(s->rdi, s->rsi, s->rdx, s->r10, s->r8);
			break;
#endif

#ifndef DISABLE_SYS_MINCORE
		case 27:
			/* mincore */
			s->rax = sys_mincore(s->rdi, s->rsi, (unsigned char *)s->rdx);
			break;
#endif

#ifndef DISABLE_SYS_MADVISE
		case 28:
			/* madvise */
			s->rax = sys_madvise(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_MADVISE */

#ifndef DISABLE_SYS_DUP2
		case 33:
			/* dup2 */
			s->rax = sys_dup2(s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_DUP2 */


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

#ifndef DISABLE_SYS_SENDFILE
		case 40:
			/* sendfile */
			s->rax = sys_sendfile(s->rdi, s->rsi, (void *)s->rdx, s->r10);
			break;
#endif

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
			s->rax = sys_connect(s->rdi, (const struct sockaddr*) s->rsi, s->rdx);
			break;
#endif
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_ACCEPT
		case 43:
			/* accept */
			s->rax = sys_accept(s->rdi, (struct sockaddr *) s->rsi, (unsigned int *)s->rdx);
			break;
#endif /* DISABLE_SYS_ACCEPT */

#ifndef DISABLE_SYS_SENDTO
		case 44:
			/* sendto */
			s->rax = sys_sendto(s->rdi, (void *)s->rsi, s->rdx, s->r10,
					(const struct sockaddr *)s->r8, s->r9);
			break;
#endif

#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_RECVFROM
		case 45:
			/* recvfrom */
			s->rax = sys_recvfrom(s->rdi, (void *)s->rsi, s->rdx, s->r10, (struct sockaddr *)s->r8, (unsigned int *)s->r9);
			break;
#endif /* DISABLE_SYS_RECVFROM */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_SHUTDOWN
		case 48:
			/* shutdown */
			s->rax = sys_shutdown(s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_SHUTDOWN */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_BIND
		case 49:
			/* bind */
			s->rax = sys_bind(s->rdi, (struct sockaddr *)s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_BIND */
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_LISTEN
		case 50:
			/* lsiten */
			s->rax = sys_listen(s->rdi, s->rsi);
			break;
#endif
#endif /* NO_NET */

#ifndef NO_NET
#ifndef DISABLE_SYS_GETSOCKNAME
		case 51:
			/* getsockname */
			s->rax = sys_getsockname(s->rdi, (struct sockaddr *)s->rsi, (unsigned int *)s->rdx);
			break;
#endif

#ifndef DISABLE_SYS_GETPEERNAME
		case 52:
			/* getpeername */
			s->rax = sys_getpeername(s->rdi, (void *)s->rsi, (void *)s->rdx);
			break;
#endif

#endif /* NO_NET */

#ifndef DISABLE_SYS_CLONE
		case 56:
			/* clone */
			s->rax = sys_clone(s->rdi, (void *)s->rsi, (int *)s->rdx,
                    (int *)s->r10, (void *)s->r8, s);
			break;
#endif /* DISABLE_SYS_CLONE */

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
			s->rax = sys_uname((void *)s->rdi);
			break;
#endif /* DISABLE_SYS_UNAME */

#ifndef DISABLE_SYS_FCNTL
		case 72:
			/* fcntl */
			s->rax = sys_fcntl(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_FCNTL */

#ifndef DISABLE_SYS_FSYNC
		case 74:
			/* fsync */
			s->rax = sys_fsync(s->rdi);
			break;
#endif

#ifndef DISABLE_SYS_FDATASYNC
		case 75:
			/* fdatasync */
			s->rax = sys_fdatasync(s->rdi);
			break;
#endif

#ifndef DISABLE_SYS_GETDENTS
		case 78:
			/* getdents */
			s->rax = sys_getdents(s->rdi, (void *)s->rsi, s->rdx);
			break;
#endif

#ifndef DISABLE_SYS_GETCWD
		case 79:
			/*getcwd */
			s->rax = sys_getcwd((char *)s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_GETCWD */

#ifndef DISABLE_SYS_CHDIR
		case 80:
			s->rax = sys_chdir((const char *)s->rdi);
			break;
#endif
		case 82:
			/* rename */

			s->rax = sys_rename((const char *)s->rdi, (const char *)s->rsi);
			break;

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

#ifndef DISABLE_SYS_CREAT
		case 85:
			/* creat */
			s->rax = sys_creat((const char *)s->rdi, s->rsi);
			break;
#endif

#ifndef DISABLE_SYS_UNLINK
		case 87:
			/* unlink */
			s->rax = sys_unlink((const char *)s->rdi);
			break;
#endif /* DISABLE_SYS_UNLINK */

#ifndef DISABLE_SYS_READLINK
		case 89:
			/* readlink */
			s->rax = sys_readlink((char *)s->rdi, (char *)s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_READLINK */

#ifndef DISABLE_SYS_UMASK
		case 95:
			/* umask */
			s->rax = sys_umask(s->rdi);
			break;
#endif

#ifndef DISABLE_SYS_GETTIMEOFDAY
		case 96:
			/* gettimeofday */
			s->rax = sys_gettimeofday((struct timeval *)s->rdi,
					(struct timezone *)s->rsi);
			break;
#endif /* DISABLE_SYS_GETTIMEOFDAY */

#ifndef DISABLE_SYS_GETRLIMIT
		case 97:
			/* getrlimit */
			s->rax = sys_getrlimit(s->rdi, (struct rlimit *)s->rsi);
			break;
#endif /* DISABLE_SYS_GETRLIMIT */

#ifndef DISABLE_SYS_SYSINFO
		case 99:
			/* sysinfo */
			s->rax = sys_sysinfo((void *)s->rdi);
			break;
#endif

#ifndef DISABLE_SYS_GETUID
		case 102:
			/* getuid */
			s->rax = sys_getuid();
			break;
#endif /* DISABLE_SYS_GETUID */

#ifndef DISABLE_SYS_GETGID
		case 104:
			s->rax = sys_getgid();
			break;
#endif /* DISABLE_SYS_GETGID */

#ifndef DISABLE_SYS_GETEUID
		case 107:
			/* geteuid */
			s->rax = sys_geteuid();
			break;
#endif /* DISABLE_SYS_GETEUID */

#ifndef DISABLE_SYS_GETEGID
		case 108:
			s->rax = sys_getegid();
			break;
#endif /* DISABLE_SYS_GETEGID */

#ifndef DISABLE_SYS_GETPPID
		case 110:
			s->rax = (long)0;
			s->rax = sys_getppid();
			break;
#endif /* DISABLE_SYS_GETPPID */

#ifndef DISABLE_SYS_SETSID
		case 112:
			s->rax = sys_setsid();
			break;
#endif

#ifndef DISABLE_SYS_SIGALTSTACK
		case 131:
			s->rax = sys_sigaltstack((const stack_t *)s->rdi, (stack_t *)s->rsi);
			break;
#endif

#ifndef DISABLE_SYS_GETPRIORITY
		case 140:
			/* getpriority */
			s->rax = sys_getpriority(s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_GETPRIORITY */

#ifndef DISABLE_SYS_SETPRIORITY
		case 141:
			/* setpriority */
			s->rax = sys_setpriority(s->rdi, s->rsi, s->rdx);
			break;
#endif

#ifndef DISABLE_SYS_ARCH_PRCTL
		case 158:
			/* arch_prctl */
			s->rax = sys_arch_prctl(s->rdi, (unsigned long *)s->rsi, (void *)s->rdx);
			break;
#endif /* DISABLE_SYS_ARCH_PRCTL */

#ifndef DISABLE_SYS_SETRLIMIT
		case 160:
			/* setrlimit */
			s->rax = sys_setrlimit(s->rdi, (void *)s->rsi);
			break;
#endif

#ifndef DISABLE_SYS_SYNC
		case 162:
			/* sync */
			s->rax = sys_sync();
			break;
#endif

#ifndef DISABLE_SYS_SETHOSTNAME
		case 170:
			/* sethostname */
			s->rax = sys_sethostname((char *)s->rdi, s->rsi);
#endif

#ifndef DISABLE_SYS_GETTID
			case 186:
				/* gettid */
				s->rax = sys_gettid();
				break;
#endif /* DISABLE_SYS_GETTID */

#ifndef DISABLE_SYS_TKILL
			case 200:
				/* tkill */
				s->rax = sys_tkill(s->rdi, s->rsi);
				break;
#endif /* DISABLE_SYS_TKILL */

#ifndef DISABLE_SYS_TIME
			case 201:
				/* time */
				s->rax = sys_time((long int *)s->rdi);
				break;
#endif /* DISABLE_SYS_TIME */

#ifndef DISABLE_SYS_FUTEX
			case 202:
				/* futex */
				s->rax = sys_futex((int *)s->rdi, s->rsi, s->rdx, (const struct timespec *)s->r10, (int *)s->r9, s->r8);
				break;
#endif /* DISABLE_SYS_FUXTEX */

#ifndef DISABLE_SYS_SCHED_SETAFFINITY
			case 203:
				s->rax = sys_sched_setaffinity(s->rdi, s->rsi, (long unsigned int *)s->rdx);
				break;
#endif /* DISABLE_SYS_SCHED_SETAFFINITY */

#ifndef DISABLE_SYS_SCHED_GETAFFINITY
			case 204:
				s->rax = sys_sched_getaffinity(s->rdi, s->rsi, (long unsigned int *)s->rdx);
				break;
#endif /* DISABLE_SYS_SCHED_GETAFFINITY */

#ifndef DISABLE_SYS_GETDENTS64
			case 217:
				/* getdents64 */
				s->rax = sys_getdents64(s->rdi, (void *)s->rsi, s->rdx);
				break;
#endif

#ifndef DISABLE_SYS_SET_TID_ADDRESS
		case 218:
			/* set_tid_address */
			s->rax = sys_set_tid_address((int *)s->rdi);
			break;
#endif /* DISABLE_SYS_SET_TID_ADDRESS */

#ifndef DISABLE_SYS_CLOCK_GETTIME
		case 228:
			/* clock_gettime */
			s->rax = sys_clock_gettime(s->rdi, (struct timespec *)s->rsi);
			break;
#endif /* DISABLE_SYS_CLOCK_GETTIME */

#ifndef DISABLE_SYS_CLOCK_GETRES
		case 229:
			/* clock_getres */
			s->rax = sys_clock_getres(s->rdi, (struct timespec *)s->rsi);
			break;
#endif

#ifndef DISABLE_SYS_TGKILL
		case 234:
			/* tgkill */
			s->rax = sys_tgkill(s->rdi, s->rsi, s->rdx);
			break;
#endif /* DISABLE_SYS_TGKILL */

#ifndef DISABLE_SYS_OPENAT
		case 257:
			s->rax = sys_openat(s->rdi, (const char *)s->rsi, s->rdx, s->r10);
			break;
#endif /* DISABLE_SYS_OPENAT */

#ifndef DISABLE_SYS_EXIT_GROUP
		case 231:
			/* exit_group */
			sys_exit_group(s->rdi);
			LOG_ERROR("Should not reach here after exit_group ... \n");
			break;
#endif /* DISABLE_SYS_EXIT_GROUP */

#ifndef DISABLE_SYS_NEWFSTATAT
        case 262:
            /* newfstatat */
            s->rax = sys_newfstatat(s->rdi, (void *)s->rsi, (void *)s->rdx,
                    s->r10);
            break;
#endif

#ifndef DISABLE_SYS_SET_ROBUST_LIST
		case 273:
			/* set_robust_list */
			s->rax = sys_set_robust_list((void *)s->rdi, s->rsi);
			break;
#endif /* DISABLE_SYS_SET_ROBUST_LIST */

#ifndef DISABLE_SYS_GET_ROBUST_LIST
		case 274:
			/* get_robust_list */
			s->rax = sys_get_robust_list(s->rdi, (void *)s->rsi, (size_t *)s->rdx);
			break;
#endif /* DISABLE_SYS_GET_ROBUST_LIST */

#ifndef DISABLE_SYS_PRLIMIT64
		case 302:
			/* prlimit64 */
			s->rax = sys_prlimit64(s->rdi, s->rsi, (struct rlimit *)s->rdx,
					(struct rlimit *)s->r10);
			break;
#endif

#ifndef DISABLE_SYS_SYNCFS
		case 306:
			/* syncfs */
			s->rax = sys_syncfs(s->rdi);
			break;
#endif

#ifndef DISABLE_SYS_GETRANDOM
		case 318:
			/* getrandom */
			s->rax = sys_getrandom((void *)s->rdi, s->rsi, s->rdx);
			break;
#endif

#ifndef DISABLE_SYS_RSEQ
		case 334:
			/* rseq */
			s->rax = sys_rseq((void *)s->rdi, s->rsi, s->rdx, s->r10);
			break;
#endif

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

	/* Notify uhyve that we have a non-recoverable page fault */
	uhyve_fault_t arg = {s->rip, s->int_no};
	uhyve_send(UHYVE_PORT_FAULT, (unsigned)virt_to_phys((size_t)&arg));

	if(tux_gdb) {
		/* We are running under gdb, put int $3 manually on the instruction
		 * source of the page fault, so that we trap to gdb from within the
		 * right context when we return there */
		*((unsigned long long int *)(s->rip)) = 0xCC;
		return;
	}

	//do_abort();
	sys_exit(-EFAULT);
}

