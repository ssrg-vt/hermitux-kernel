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

#include <hermit/spinlock.h>
#include <hermit/semaphore.h>
#include <hermit/time.h>
#include <hermit/rcce.h>
#include <hermit/memory.h>
#include <hermit/signal.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/io.h>
#include <sys/poll.h>

spinlock_t readwritev_spinlock = SPINLOCK_INIT;

#define HERMITUX_HOSTNAME_LEN 65 /* Should not be greater than 65 to fit in struct
						   utsname */
/*
 * Note that linker symbols are not variables, they have no memory allocated for
 * maintaining a value, rather their address is their value.
 */
extern const void kernel_start;

//TODO: don't use one big kernel lock to comminicate with all proxies
spinlock_irqsave_t lwip_lock = SPINLOCK_IRQSAVE_INIT;

extern spinlock_irqsave_t stdio_lock;
extern int32_t isle;
extern int32_t possible_isles;
extern volatile int libc_sd;

static inline int socket_send(int fd, const 	void* buf, size_t len)
{
	int ret, sz = 0;

	do {
		ret = lwip_write(fd, (char*)buf + sz, len-sz);
		if (ret >= 0)
			sz += ret;
		else
			return ret;
	} while(sz < len);

	return len;
}

static inline int socket_recv(int fd, void* buf, size_t len)
{
	int ret, sz = 0;

	do {
		ret = lwip_read(fd, (char*)buf + sz, len-sz);
		if (ret >= 0)
			sz += ret;
		else
			return ret;
	} while(sz < len);

	return len;
}

tid_t sys_getpid(void)
{
	task_t* task = per_core(current_task);

	return task->id;
}

int sys_getprio(tid_t* id)
{
	task_t* task = per_core(current_task);

	if (!id || (task->id == *id))
		return task->prio;
	return -EINVAL;
}

int sys_setprio(tid_t* id, int prio)
{
	return -ENOSYS;
}

void NORETURN do_exit(int arg);

typedef struct {
	int sysnr;
	int arg;
} __attribute__((packed)) sys_exit_t;

/** @brief To be called by the systemcall to exit tasks */
void NORETURN sys_exit(int arg)
{
	if (is_uhyve()) {
		uhyve_send(UHYVE_PORT_EXIT, (unsigned) virt_to_phys((size_t) &arg));
	} else {
		sys_exit_t sysargs = {__NR_exit, arg};

		spinlock_irqsave_lock(&lwip_lock);
		if (libc_sd >= 0)
		{
			int s = libc_sd;

			socket_send(s, &sysargs, sizeof(sysargs));
			libc_sd = -1;

			spinlock_irqsave_unlock(&lwip_lock);

			// switch to LwIP thread
			reschedule();

			lwip_close(s);
		} else {
			spinlock_irqsave_unlock(&lwip_lock);
		}
	}

	do_exit(arg);
}

typedef struct {
	int sysnr;
	int fd;
	size_t len;
} __attribute__((packed)) sys_read_t;

typedef struct {
	int fd;
	char* buf;
        size_t len;
	ssize_t ret;
} __attribute__((packed)) uhyve_read_t;

ssize_t sys_read(int fd, char* buf, size_t len)
{
	sys_read_t sysargs = {__NR_read, fd, len};
	ssize_t j, ret;

	// do we have an LwIP file descriptor?
	if (fd & LWIP_FD_BIT) {
		spinlock_irqsave_lock(&lwip_lock);
		ret = lwip_read(fd & ~LWIP_FD_BIT, buf, len);
		spinlock_irqsave_unlock(&lwip_lock);
		if (ret < 0)
			return -errno;

		return ret;
	}

	if (is_uhyve()) {
		uhyve_read_t uhyve_args = {fd, (char*) buf, len, -1};

		uhyve_send(UHYVE_PORT_READ, (unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.ret;
	}

	if (libc_sd < 0)
		return -ENOSYS;

	spinlock_irqsave_lock(&lwip_lock);

	int s = libc_sd;
	socket_send(s, &sysargs, sizeof(sysargs));
	socket_recv(s, &j, sizeof(j));

	ssize_t i=0;
	while(i < j)
	{
		ret = lwip_read(s, (char*)buf+i, j-i);
		if (ret < 0) {
			spinlock_irqsave_unlock(&lwip_lock);
			return ret;
		}

		i += ret;
	}

	spinlock_irqsave_unlock(&lwip_lock);

	return j;
}

ssize_t readv(int d, const struct iovec *iov, int iovcnt)
{
	return -ENOSYS;
}

typedef struct {
	int sysnr;
	int fd;
	size_t len;
} __attribute__((packed)) sys_write_t;

typedef struct {
	int fd;
	const char* buf;
	size_t len;
} __attribute__((packed)) uhyve_write_t;

ssize_t sys_write(int fd, const char* buf, size_t len)
{
	if (BUILTIN_EXPECT(!buf, 0))
		return -EINVAL;

	ssize_t i, ret;
	sys_write_t sysargs = {__NR_write, fd, len};

	// do we have an LwIP file descriptor?
	if (fd & LWIP_FD_BIT) {
		spinlock_irqsave_lock(&lwip_lock);
		ret = lwip_write(fd & ~LWIP_FD_BIT, buf, len);
		spinlock_irqsave_unlock(&lwip_lock);
		if (ret < 0)
			return -errno;

		return ret;
	}

	if (is_uhyve()) {
		uhyve_write_t uhyve_args = {fd, (const char*) buf, len};

		uhyve_send(UHYVE_PORT_WRITE, (unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.len;
	}

	if (libc_sd < 0)
	{
		spinlock_irqsave_lock(&stdio_lock);
		for(i=0; i<len; i++)
			kputchar(buf[i]);
		spinlock_irqsave_unlock(&stdio_lock);

		return len;
	}

	spinlock_irqsave_lock(&lwip_lock);

	int s = libc_sd;
	socket_send(s, &sysargs, sizeof(sysargs));

	i=0;
	while(i < len)
	{
		ret = lwip_write(s, (char*)buf+i, len-i);
		if (ret < 0) {
			spinlock_irqsave_unlock(&lwip_lock);
			return ret;
		}

		i += ret;
	}

	if (fd > 2)
		i = socket_recv(s, &i, sizeof(i));

	spinlock_irqsave_unlock(&lwip_lock);

	return i;
}

ssize_t writev(int fildes, const struct iovec *iov, int iovcnt)
{
	return -ENOSYS;
}

ssize_t sys_sbrk(ssize_t incr)
{
	ssize_t ret;
	vma_t* heap = per_core(current_task)->heap;
	static spinlock_t heap_lock = SPINLOCK_INIT;

	if (BUILTIN_EXPECT(!heap, 0)) {
		LOG_ERROR("sys_sbrk: missing heap!\n");
		do_abort();
	}

	spinlock_lock(&heap_lock);

	ret = heap->end;

	// check heapp boundaries
	if ((heap->end >= HEAP_START) && (heap->end+incr < HEAP_START + HEAP_SIZE)) {
		heap->end += incr;

		// reserve VMA regions
		if (PAGE_FLOOR(heap->end) > PAGE_FLOOR(ret)) {
			// region is already reserved for the heap, we have to change the
			// property
			vma_free(PAGE_FLOOR(ret), PAGE_CEIL(heap->end));
			vma_add(PAGE_FLOOR(ret), PAGE_CEIL(heap->end), VMA_HEAP|VMA_USER);
		}
	} else ret = -ENOMEM;

	// allocation and mapping of new pages for the heap
	// is catched by the pagefault handler

	spinlock_unlock(&heap_lock);

	return ret;
}

typedef struct {
	const char* name;
	int flags;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_open_t;

int sys_open(const char* name, int flags, int mode)
{
	if (is_uhyve()) {
		uhyve_open_t uhyve_open = {(const char*)virt_to_phys((size_t)name), flags, mode, -1};

		uhyve_send(UHYVE_PORT_OPEN, (unsigned)virt_to_phys((size_t) &uhyve_open));

		return uhyve_open.ret;
	}

	int s, i, ret, sysnr = __NR_open;
	size_t len;

	spinlock_irqsave_lock(&lwip_lock);
	if (libc_sd < 0) {
		ret = -EINVAL;
		goto out;
	}

	s = libc_sd;
	len = strlen(name)+1;

	//i = 0;
	//lwip_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &i, sizeof(i));

	ret = socket_send(s, &sysnr, sizeof(sysnr));
	if (ret < 0)
		goto out;

	ret = socket_send(s, &len, sizeof(len));
	if (ret < 0)
		goto out;

	i=0;
	while(i<len)
	{
		ret = socket_send(s, name+i, len-i);
		if (ret < 0)
			goto out;
		i += ret;
	}

	ret = socket_send(s, &flags, sizeof(flags));
	if (ret < 0)
		goto out;

	ret = socket_send(s, &mode, sizeof(mode));
	if (ret < 0)
		goto out;

	//i = 1;
	//lwip_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &i, sizeof(i));

	socket_recv(s, &ret, sizeof(ret));

out:
	spinlock_irqsave_unlock(&lwip_lock);

	return ret;
}

typedef struct {
	int sysnr;
	int fd;
} __attribute__((packed)) sys_close_t;

typedef struct {
        int fd;
        int ret;
} __attribute__((packed)) uhyve_close_t;


const size_t hermitux_hostname_len = HERMITUX_HOSTNAME_LEN;
char hermitux_hostname[128] = "hermitux";

/* Timing syscalls (gettimeofday, time, clock_gettime) will return values
 * relative to the boot time stamp counter. This is called by the kernel at
 * boot time */
unsigned long long syscall_boot_tsc = 0;
unsigned long long syscall_freq = 0;

void syscall_timing_init() {
#ifdef __aarch64__
#warning "Missing implementation"
#else
	unsigned int lo, hi;

	asm volatile ("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
	syscall_boot_tsc = ((unsigned long long)hi << 32ULL | (unsigned long long)lo);
	syscall_freq = get_cpu_frequency() * 1000000ULL;
#endif
}

static spinlock_irqsave_t malloc_lock = SPINLOCK_IRQSAVE_INIT;

void __sys_malloc_lock(void)
{
	spinlock_irqsave_lock(&malloc_lock);
}

void __sys_malloc_unlock(void)
{
	spinlock_irqsave_unlock(&malloc_lock);
}

static spinlock_irqsave_t env_lock = SPINLOCK_IRQSAVE_INIT;

void __sys_env_lock(void)
{
	spinlock_irqsave_lock(&env_lock);
}

void __sys_env_unlock(void)
{
	spinlock_irqsave_unlock(&env_lock);
}
