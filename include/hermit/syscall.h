/*
 * Copyright (c) 2011, Stefan Lankes, RWTH Aachen University
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
 * @file include/hermit/syscall.h
 * @brief System call number definitions
 *
 * This file contains define constants for every syscall's number.
 */

#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#ifdef __KERNEL__
#include <hermit/stddef.h>
#include <lwip/sockets.h>
#include <hermit/hermitux_syscalls.h>
#else
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef NORETURN
#define NORETURN	__attribute__((noreturn))
#endif

typedef unsigned int tid_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

struct sem;
typedef struct sem sem_t;

typedef void (*signal_handler_t)(int);
typedef unsigned id_t;

/*
 * HermitCore is a libOS.
 * => classical system calls are realized as normal function
 * => forward declaration of system calls as function
 */
tid_t sys_getpid(void);
tid_t sys_getppid(void);
int sys_fork(void);
int sys_wait(int* status);
int sys_execve(const char* name, char * const * argv, char * const * env);
int sys_getprio(tid_t* id);
int sys_getpriority(int which, id_t who);
int sys_setprio(tid_t* id, int prio);
int sys_setpriority(int which, id_t who, int prio);
void NORETURN sys_exit(int arg);
void NORETURN sys_exit_group(int arg);
ssize_t sys_read(int fd, char* buf, size_t len);
ssize_t sys_write(int fd, const char* buf, size_t len);
ssize_t sys_sbrk(ssize_t incr);
int sys_open(const char* name, int flags, int mode);
int sys_close(int fd);
void sys_msleep(unsigned int ms);
int sys_sem_init(sem_t** sem, unsigned int value);
int sys_sem_destroy(sem_t* sem);
int sys_sem_wait(sem_t* sem);
int sys_sem_post(sem_t* sem);
int sys_sem_timedwait(sem_t *sem, unsigned int ms);
int sys_sem_cancelablewait(sem_t* sem, unsigned int ms);
int sys_clone(unsigned long clone_flags, void *stack, int *ptid, int *ctid,
		void *arg, void *ep);
off_t sys_lseek(int fd, off_t offset, int whence);
size_t sys_get_ticks(void);
int sys_rcce_init(int session_id);
size_t sys_rcce_malloc(int session_id, int ue);
int sys_rcce_fini(int session_id);
void sys_yield(void);
int sys_kill(tid_t dest, int signum);
int sys_signal(signal_handler_t handler);

/* Pierre */
struct utsname;
struct stat;
struct iovec;
struct timespec;
struct timeval;
struct sigaction;
struct sockaddr;
struct rlimit;
struct sysinfo;
typedef struct fd_set fd_set;
typedef unsigned short umode_t;
typedef uint32_t socklen_t;

int sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
int sys_writev(int fd, const struct iovec *iov, unsigned long vlen);
int sys_readv(int fd, const struct iovec *iov, unsigned long vlen);
int sys_clock_gettime(clockid_t clk_id, struct timespec *tp);
int sys_gettimeofday(struct timeval *tv, struct timezone *tz);
int sys_nanosleep(struct timespec *req, struct timespec *rem);
ssize_t sys_brk(ssize_t val);
int sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
int sys_unlink(const char *pathname);
int sys_arch_prctl(int option, unsigned long *arg2, unsigned long *addr);
int sys_uname(struct utsname *buf);
int sys_fstat(int fd, struct stat *buf);
int sys_stat(const char *pathname, struct stat *buf);
int sys_lstat(const char *pathname, struct stat *buf);
int sys_getcwd(char *buf, size_t size);
int sys_rt_sigaction(int signum, struct sigaction *act,
		struct sigaction *oldact);
int sys_socket(int domain, int type, int protocol);
int sys_bind(int fd, struct sockaddr *addr, int addrlen);
int sys_setsockopt(int fd, int level, int optname, char *optval,
		socklen_t optlen);
size_t sys_mmap(unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long fd, unsigned long off);
int sys_mkdir(const char *pathname, umode_t mode);
int sys_rmdir(const char *pathname);
int sys_madvise(unsigned long start, size_t len_in, int behavior);
int sys_geteuid(void);
int sys_getuid(void);
int sys_getgid(void);
int sys_getegid(void);
int sys_openat(int dirfd, const char *pathname, int flags, int mode);
int sys_tgkill(int tgid, int tid, int sig);
int sys_readlink(char *path, char *buf, int bufsiz);
int sys_access(const char *pathname, int mode);
int sys_time(long *tloc);
int sys_sched_setaffinity(int pid, unsigned int len,
		unsigned long *user_mask_ptr);
long sys_mprotect(size_t addr, size_t len, unsigned long prot);
int sys_munmap(size_t viraddr, size_t len);
int sys_sched_getaffinity(int pid, unsigned int len,
		unsigned long *user_mask_ptr);
int sys_futex(int *uaddr, int futex_op, int val, const struct timespec *timeout,
		int *uaddr2, int val3);
int sys_sched_yield(void);
long sys_getrlimit(unsigned int resource, struct rlimit *rlim);
long sys_get_robust_list(int pid, void *head_ptr, size_t *len_ptr);
long sys_set_robust_list(void *head, size_t len);
int sys_sysinfo(struct sysinfo *info);
int sys_prlimit64(int pid, unsigned int resource, struct rlimit *new_rlim,
		struct rlimit *old_rlim);
int sys_clock_getres(clockid_t id, struct timespec *tp);
int sys_sethostname(char *name, size_t len);
int sys_setrlimit(int resource, const struct rlimit *rlim);
int sys_tkill(int tid, int sig);
int sys_gettid(void);
int sys_mincore(unsigned long start, size_t len, unsigned char *vec);
long sys_sigaltstack(const stack_t *ss, stack_t *oss);
int sys_select(int maxfdp1, fd_set *readset, fd_set *writeset,
		fd_set *exceptset, struct timeval *timeout);
int sys_sendto(int s, const void *dataptr, size_t size, int flags,
		const struct sockaddr *to, socklen_t tolen);
int sys_chdir(const char *path);

struct ucontext;
typedef struct ucontext ucontext_t;

void makecontext(ucontext_t *ucp, void (*func)(), int argc, ...);
int swapcontext(ucontext_t *oucp, const ucontext_t *ucp);
int getcontext(ucontext_t *ucp);
int setcontext(ucontext_t *ucp);

#define __NR_exit 		0
#define __NR_write		1
#define __NR_open		2
#define __NR_close		3
#define __NR_read		4
#define __NR_lseek		5
#define __NR_unlink		6
#define __NR_getpid		7
#define __NR_kill		8
#define __NR_fstat		9
#define __NR_sbrk		10
#define __NR_fork		11
#define __NR_wait		12
#define __NR_execve		13
#define __NR_times		14
#define __NR_stat		15
#define __NR_dup		16
#define __NR_dup2		17
#define __NR_msleep		18
#define __NR_yield		19
#define __NR_sem_init		20
#define __NR_sem_destroy	21
#define __NR_sem_wait		22
#define __NR_sem_post		23
#define __NR_sem_timedwait	24
#define __NR_getprio		25
#define __NR_setprio		26
#define __NR_clone		27
#define __NR_sem_cancelablewait	28
#define __NR_get_ticks		29

#ifndef __KERNEL__
inline static long
syscall(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
	long res;

	// note: syscall stores the return address in rcx and rflags in r11
	asm volatile ("syscall"
		: "=a" (res)
		: "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		: "memory", "%rcx", "%r11");

	return res;
}

#define SYSCALL0(NR) \
	syscall(NR, 0, 0, 0)
#define SYSCALL1(NR, ARG0) \
	syscall(NR, (unsigned long)ARG0, 0, 0)
#define SYSCALL2(NR, ARG0, ARG1) \
	syscall(NR, (unsigned long)ARG0, (unsigned long)ARG1, 0)
#define SYSCALL3(NR, ARG0, ARG1, ARG2) \
	syscall(NR, (unsigned long)ARG0, (unsigned long)ARG1, (unsigned long)ARG2)
#endif // __KERNEL__

#ifdef __cplusplus
}
#endif

#endif
