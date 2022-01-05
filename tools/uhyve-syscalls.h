/* Copyright (c) 2017, RWTH Aachen University
 * Author(s): Daniel Krebs <github@daniel-krebs.net>
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef UHYVE_SYSCALLS_H
#define UHYVE_SYSCALLS_H

#include <unistd.h>
#include <stddef.h>

typedef enum {
	UHYVE_PORT_WRITE		= 0x499,
	UHYVE_PORT_OPEN			= 0x500,
	UHYVE_PORT_CLOSE		= 0x501,
	UHYVE_PORT_READ			= 0x502,
	UHYVE_PORT_EXIT			= 0x503,
	UHYVE_PORT_LSEEK		= 0x504,
	/* 0x505 to 0x508 are taken by uhyve network commands */
	UHYVE_PORT_UNLINK		= 0x509,
	UHYVE_PORT_GETDENTS64	= 0x510,
	UHYVE_PORT_CMDSIZE		= 0x511,
	UHYVE_PORT_CMDVAL		= 0x512,
	UHYVE_PORT_FSTAT		= 0x513,
	UHYVE_PORT_GETCWD		= 0x514,
	UHYVE_PORT_MKDIR    	= 0x515,
	UHYVE_PORT_RMDIR    	= 0x516,
	UHYVE_PORT_ACCESS   	= 0x517,
	UHYVE_PORT_PFAULT   	= 0x518,
	UHYVE_PORT_FAULT   		= 0x519,
	UHYVE_PORT_READLINK 	= 0x520,
	UHYVE_PORT_MINIFS_LOAD 	= 0x521,
	UHYVE_PORT_FCNTL		= 0x522,
	UHYVE_PORT_OPENAT		= 0x523,
	UHYVE_PORT_CREAT		= 0x524,
	UHYVE_PORT_SYNC 		= 0x525,
	UHYVE_PORT_FSYNC 		= 0x526,
	UHYVE_PORT_FDATASYNC	= 0x527,
	UHYVE_PORT_SYNCFS		= 0x528,
	UHYVE_PORT_GETDENTS		= 0x529,
	UHYVE_PORT_DUP2			= 0X530,
	UHYVE_PORT_PIPE			= 0X531,
	UHYVE_PORT_NEWFSTATAT	= 0X532,
	UHYVE_PORT_RENAME = 0X533
} uhyve_syscall_t;

typedef struct {
	int fd;
	const char* buf;
	size_t len;
	int ret;
} __attribute__((packed)) uhyve_write_t;

typedef struct {
	const char* pathname;
	int ret;
} __attribute__((packed)) uhyve_unlink_t;

typedef struct {
	const char* name;
	int flags;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_open_t;

typedef struct {
	int fd;
	int ret;
} __attribute__((packed)) uhyve_close_t;

typedef struct {
	int fd;
	char* buf;
	size_t len;
	ssize_t ret;
} __attribute__((packed)) uhyve_read_t;

typedef struct {
	int fd;
	off_t offset;
	int whence;
} __attribute__((packed)) uhyve_lseek_t;

typedef struct {
	int argc;
	int argsz[128];
	int envc;
	int envsz[128];
} __attribute__ ((packed)) uhyve_cmdsize_t;

typedef struct {
	char **argv;
	char **envp;
} __attribute__ ((packed)) uhyve_cmdval_t;

typedef struct {
	int fd;
	int ret;
	struct stat *st;
} __attribute__ ((packed)) uhyve_fstat_t;

typedef struct {
	char *buf;
	size_t size;
	int ret;
} __attribute__ ((packed)) uhyve_getcwd_t;

typedef unsigned short umode_t;
typedef struct {
	const char *pathname;
	umode_t mode;
	int ret;
} __attribute__ ((packed)) uhyve_mkdir_t;

typedef struct {
	const char *pathname;
	int ret;
} __attribute__ ((packed)) uhyve_rmdir_t;

typedef struct {
	char *pathname;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_access_t;

typedef struct {
	uint64_t rip;
	uint64_t addr;
} __attribute__ ((packed)) uhyve_pfault_t;

typedef struct {
	uint64_t rip;
	uint32_t int_no;
} __attribute__ ((packed)) uhyve_fault_t;

typedef struct {
	char *path;
	char* buf;
	int bufsz;
	ssize_t ret;
} __attribute__((packed)) uhyve_readlink_t;

/* Warning: this needs to be consistent with what is in kernel/minifs.c! */
#define MINIFS_LOAD_MAXPATH		128
typedef struct {
	char hostpath[MINIFS_LOAD_MAXPATH];
	char guestpath[MINIFS_LOAD_MAXPATH];
} __attribute__((packed)) uhyve_minifs_load_t;

typedef struct {
	int fd;
	struct linux_dirent64 *dirp;
	unsigned int count;
	int ret;
} __attribute__((packed)) uhyve_getdeents64_t;

typedef struct {
	int fd;
	unsigned int cmd;
	unsigned long arg;
	int ret;
} __attribute__((packed)) uhyve_fcntl_t;

typedef struct {
	int dirfd;
	const char* name;
	int flags;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_openat_t;

typedef struct {
	char *path;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_creat_t;

typedef struct {
	char *oldpath;
	char *newpath;
	int ret;
} __attribute__((packed)) uhyve_rename_t;

typedef struct {
	int fd;
	int ret;
} __attribute__((packed)) uhyve_fsync_t;

typedef struct {
	int fd;
	struct linux_dirent *dirp;
	unsigned int count;
	int ret;
} __attribute__((packed)) uhyve_getdeents_t;

typedef struct {
	int oldfd;
	int newfd;
	int ret;
} __attribute__ ((packed)) uhyve_dup2_t;

typedef struct {
    int *filedes;
    int ret;
} uhyve_pipe_t;

typedef struct {
	int dirfd;
	const char* name;
	struct stat *st;
	int flag;
    int ret;
} __attribute__((packed)) uhyve_newfstatat_t;

#endif // UHYVE_SYSCALLS_H

