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

#ifndef __STDDEF_H__
#define __STDDEF_H__

/**
 * @author Stefan Lankes
 * @file include/hermit/stddef.h
 * @brief Definition of basic data types
 */

#include <hermit/config.h>
#include <asm/stddef.h>
#include <asm/irqflags.h>

#ifdef __cplusplus
extern "C" {
#endif

// size of the whole application
extern size_t image_size;

/* Linux binary size */
extern uint64_t tux_size;
extern uint64_t tux_start_address;

#define TIMER_FREQ	100 /* in HZ */
#define CLOCK_TICK_RATE	1193182 /* 8254 chip's internal oscillator frequency */
#define CACHE_LINE	64
#define HEAP_START	(PAGE_CEIL(tux_start_address + tux_size) + 4*PAGE_SIZE)
/* As opposed to HermitCore we can have a reduced heap size as most of native
 * Linux C libraries will rely on mmap for large memory allocations. */
#define HEAP_SIZE	(1ULL << 20)
#define KMSG_SIZE	0x4000
#define INT_SYSCALL	0x80
#define MAILBOX_SIZE	128
//#define WITH_PCI_IDS

#define BYTE_ORDER             LITTLE_ENDIAN

/* Dynamic ticks causes issues with hermitux multithreading, disable it for
 * now */
/* #define DYNAMIC_TICKS */

#define UHYVE_PORT_WRITE		0x400
#define UHYVE_PORT_OPEN			0x440
#define UHYVE_PORT_CLOSE		0x480
#define UHYVE_PORT_READ			0x500
#define UHYVE_PORT_EXIT			0x540
#define UHYVE_PORT_LSEEK		0x580

// Networkports
#define UHYVE_PORT_NETINFO		0x600
#define UHYVE_PORT_NETWRITE		0x640
#define UHYVE_PORT_NETREAD		0x680
#define UHYVE_PORT_NETSTAT		0x700
#define UHYVE_PORT_FREELIST		0x720

/* Ports and data structures for uhyve command line arguments and envp
 * forwarding */
#define UHYVE_PORT_CMDSIZE		0x740
#define UHYVE_PORT_CMDVAL		0x780

#define UHYVE_PORT_GETDENTS64		0x840
#define UHYVE_PORT_FSTAT		0xA40
#define UHYVE_PORT_GETCWD		0xA80
#define UHYVE_PORT_MKDIR		0xAC0
#define UHYVE_PORT_RMDIR		0xB00
#define UHYVE_PORT_ACCESS		0xB40
#define UHYVE_PORT_PFAULT		0xB80
#define UHYVE_PORT_FAULT		0xBC0
#define UHYVE_PORT_READLINK		0xC00
#define UHYVE_PORT_MINIFS_LOAD		0xC40
#define UHYVE_PORT_FCNTL 		0xC80
#define UHYVE_PORT_OPENAT 		0xCA0
#define UHYVE_PORT_CREAT 		0xD00
#define UHYVE_PORT_SYNC 		0xD40
#define UHYVE_PORT_FSYNC 		0xD80
#define UHYVE_PORT_FDATASYNC		0xDC0
#define UHYVE_PORT_SYNCFS		0xE00
#define UHYVE_PORT_GETDENTS		0xE40
#define UHYVE_PORT_UNLINK		0xE80
#define UHYVE_PORT_READLINKAT	0xEC0
#define UHYVE_PORT_FACCESSAT	0xF00
#define UHYVE_PORT_NEWFSTATAT	0xF40
#define UHYVE_PORT_MKDIRAT	    0xF80
#define UHYVE_PORT_UNLINKAT     0xFC0

#define BUILTIN_EXPECT(exp, b)		__builtin_expect((exp), (b))
//#define BUILTIN_EXPECT(exp, b)	(exp)
#define NORETURN			__attribute__((noreturn))

#define NULL 		((void*) 0)

/// represents a task identifier
typedef unsigned int tid_t;

#define DECLARE_PER_CORE(type, name) extern type name __attribute__ ((section (".percore")))
#define DEFINE_PER_CORE(type, name, def_value) type name __attribute__ ((section (".percore"))) = def_value
#define DEFINE_PER_CORE_STATIC(type, name, def_value) static type name __attribute__ ((section (".percore"))) = def_value

/* needed to find the task, which is currently running on this core */
struct task;
DECLARE_PER_CORE(struct task*, current_task);

#if MAX_CORES > 1
/* allows fast access to the core id */
DECLARE_PER_CORE(uint32_t, __core_id);
#define CORE_ID per_core(__core_id)
#else
#define CORE_ID 0
#endif

#ifdef __cplusplus
}
#endif

#endif
