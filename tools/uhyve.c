/* Copyright (c) 2015, IBM
 * Author(s): Dan Williams <djwillia@us.ibm.com>
 *            Ricardo Koller <kollerr@us.ibm.com>
 * Copyright (c) 2017, RWTH Aachen University
 * Author(s): Stefan Lankes <slankes@eonerc.rwth-aachen.de>
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

/* We used several existing projects as guides
 * kvmtest.c: http://lwn.net/Articles/658512/
 * Solo5: https://github.com/Solo5/solo5
 */

/*
 * 15.1.2017: extend original version (https://github.com/Solo5/solo5)
 *            for HermitCore
 * 25.2.2017: add SMP support to enable more than one core
 * 24.4.2017: add checkpoint/restore support,
 *            remove memory limit
 */

 #define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <elf.h>
#include <err.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/eventfd.h>
#include <linux/const.h>
#include <linux/kvm.h>
#include <asm/mman.h>
#include <sys/syscall.h>

#include "uhyve.h"
#include "uhyve-cpu.h"
#include "uhyve-syscalls.h"
#include "uhyve-net.h"
#include "uhyve-elf.h"
#include "proxy.h"
#include "uhyve-gdb.h"
#include "uhyve-msr.h"
#include "uhyve-profiler.h"

#include "miniz.h"
#include "mini_gzip.h"

#include "uhyve-seccomp.h"

// define this macro to create checkpoints with KVM's dirty log
#define USE_DIRTY_LOG

#define MAX_FNAME	256
#define MAX_MSR_ENTRIES	25

#define CPUID_FUNC_PERFMON	0x0A
#define GUEST_PAGE_SIZE		0x200000   /* 2 MB pages in guest */

#define BOOT_GDT	0x1000
#define BOOT_INFO	0x2000
#define BOOT_PML4	0x10000
#define BOOT_PDPTE	0x11000
#define BOOT_PDE	0x12000

#define BOOT_GDT_NULL	0
#define BOOT_GDT_CODE	1
#define BOOT_GDT_DATA	2
#define BOOT_GDT_MAX	3

#define KVM_32BIT_MAX_MEM_SIZE	(1ULL << 32)
#define KVM_32BIT_GAP_SIZE	(768 << 20)
#define KVM_32BIT_GAP_START	(KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE)

/// Page offset bits
#define PAGE_BITS			12
#define PAGE_2M_BITS	21
#define PAGE_SIZE			(1L << PAGE_BITS)
/// Mask the page address without page map flags and XD flag
#if 0
#define PAGE_MASK		((~0L) << PAGE_BITS)
#define PAGE_2M_MASK		(~0L) << PAGE_2M_BITS)
#else
#define PAGE_MASK			(((~0UL) << PAGE_BITS) & ~PG_XD)
#define PAGE_2M_MASK	(((~0UL) << PAGE_2M_BITS) & ~PG_XD)
#endif

// Page is present
#define PG_PRESENT		(1 << 0)
// Page is read- and writable
#define PG_RW			(1 << 1)
// Page is addressable from userspace
#define PG_USER			(1 << 2)
// Page write through is activated
#define PG_PWT			(1 << 3)
// Page cache is disabled
#define PG_PCD			(1 << 4)
// Page was recently accessed (set by CPU)
#define PG_ACCESSED		(1 << 5)
// Page is dirty due to recent write-access (set by CPU)
#define PG_DIRTY		(1 << 6)
// Huge page: 4MB (or 2MB, 1GB)
#define PG_PSE			(1 << 7)
// Page attribute table
#define PG_PAT			PG_PSE
#if 1
/* @brief Global TLB entry (Pentium Pro and later)
 *
 * HermitCore is a single-address space operating system
 * => CR3 never changed => The flag isn't required for HermitCore
 */
#define PG_GLOBAL		0
#else
#define PG_GLOBAL		(1 << 8)
#endif
// This table is a self-reference and should skipped by page_map_copy()
#define PG_SELF			(1 << 9)

/// Disable execution for this page
#define PG_XD			(1L << 63)

#define BITS					64
#define PHYS_BITS			52
#define VIRT_BITS			48
#define PAGE_MAP_BITS	9
#define PAGE_LEVELS		4

// Networkports
#define UHYVE_PORT_NETINFO		0x505
#define UHYVE_PORT_NETWRITE		0x506
#define UHYVE_PORT_NETREAD		0x507
#define UHYVE_PORT_NETSTAT		0x508

#define UHYVE_IRQ	11

#define IOAPIC_DEFAULT_BASE	0xfec00000
#define APIC_DEFAULT_BASE	0xfee00000


static bool restart = false;
static bool cap_tsc_deadline = false;
static bool cap_irqchip = false;
static bool cap_adjust_clock_stable = false;
static bool cap_irqfd = false;
static bool cap_vapic = false;
static bool full_checkpoint = false;
static uint32_t ncores = 1;
static uint8_t* klog = NULL;
uint8_t* mboot = NULL;
static uint64_t elf_entry;
static pthread_t* vcpu_threads = NULL;
static pthread_t net_thread;
static int* vcpu_fds = NULL;
static int kvm = -1, efd = -1;
int vmfd = -1, netfd = -1;
static uint32_t no_checkpoint = 0;
static pthread_mutex_t kvm_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;
static __thread struct kvm_run *run = NULL;
static __thread int vcpufd = -1;
static __thread uint32_t cpuid = 0;
static sem_t net_sem;
static bool uhyve_gdb_enabled = false;
static bool uhyve_profiler_enabled = false;
bool uhyve_seccomp_enabled = false;
char htux_bin[PATH_MAX+1];
char htux_kernel[PATH_MAX+1];

size_t guest_size = 0x20000000ULL;
uint8_t* guest_mem = NULL;

int uhyve_argc = -1;
int uhyve_envc = -1;
char **uhyve_argv = NULL;
extern char **environ;
char **uhyve_envp = NULL; 

static uint64_t memparse(const char *ptr)
{
	// local pointer to end of parsed string
	char *endptr;

	// parse number
	uint64_t size = strtoull(ptr, &endptr, 0);

	// parse size extension, intentional fall-through
	switch (*endptr) {
	case 'E':
	case 'e':
		size <<= 10;
	case 'P':
	case 'p':
		size <<= 10;
	case 'T':
	case 't':
		size <<= 10;
	case 'G':
	case 'g':
		size <<= 10;
	case 'M':
	case 'm':
		size <<= 10;
	case 'K':
	case 'k':
		size <<= 10;
		endptr++;
	default:
		break;
	}

	return size;
}

// Just close file descriptor if not already done
static inline void close_fd(int* fd)
{
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

static void uhyve_exit(void* arg)
{
	if (pthread_mutex_trylock(&kvm_lock))
	{
		if (vcpufd > 0)
			close_fd(&vcpufd);
		return;
	}

	// only the main thread will execute this
	if (vcpu_threads) {
		for(uint32_t i=0; i<ncores; i++) {
			if (pthread_self() == vcpu_threads[i])
				continue;

			pthread_kill(vcpu_threads[i], SIGTERM);
		}

		if (netfd > 0)
			pthread_kill(net_thread, SIGTERM);
	}

	if (vcpufd > 0)
		close_fd(&vcpufd);
}

static void uhyve_atexit(void)
{
	uhyve_exit(NULL);

	if(uhyve_profiler_enabled)
		uhyve_profiler_exit();

	if (vcpu_threads) {
		for(uint32_t i = 0; i < ncores; i++) {
			if (pthread_self() == vcpu_threads[i])
				continue;
			pthread_join(vcpu_threads[i], NULL);
		}

		free(vcpu_threads);
	}

	if (vcpu_fds)
		free(vcpu_fds);

	if (klog && verbose)
	{
		fputs("\nDump kernel log:\n", stderr);
		fputs("================\n", stderr);
		fprintf(stderr, "%s\n", klog);
	}

	// clean up and close KVM
	if (vmfd > 0)
		close_fd(&vmfd);
	if (kvm > 0)
		close_fd(&kvm);
}

static int load_kernel(uint8_t* mem, const char* path)
{
	Elf64_Ehdr hdr;
	Elf64_Phdr *phdr = NULL;
	size_t buflen;
	size_t total_size = 0;
	int fd, ret;
	int first_load = 1;
	char *compr_in, *compr_out;
	const char *gz_extension = path + strlen(path) - 3;
	int  is_compressed = !(strcmp(gz_extension, ".gz"));

	if(is_compressed) {
		struct mini_gzip gz;
		struct stat st;
		int fd, ret;
		int output_file_size = 5*1024*1024;

		printf("Compressed kernel detected, uncompressing...\n");

		fd = open(path, O_RDONLY);
		if(fd == -1) {
			fprintf(stderr, "open %s: %s\n", path, strerror(errno));
			return -1;
		}

		ret = fstat(fd, &st);
		if(ret) {
			fprintf(stderr, "stat %s: %s\n", path, strerror(errno));
			return -1;
		}

		compr_in = malloc(st.st_size);
		compr_out = malloc(output_file_size);

		ret = read(fd, compr_in, st.st_size);
		if(ret != st.st_size) {
			fprintf(stderr, "read %s: %s\n", path, strerror(errno));
			close(fd); goto out;
		}

		ret = mini_gz_start(&gz, compr_in, st.st_size);
		if(ret != 0) {
			fprintf(stderr, "error init uncompressing %s\n", path);
			close(fd); goto out;
		}

		mini_gz_unpack(&gz, compr_out, 5*1024*1024);
	}

	fd = open(path, O_RDONLY);
	if (fd == -1)
	{
		perror("Unable to open file");
		return -1;
	}

	if(is_compressed)
		memcpy(&hdr, compr_out, sizeof(hdr));
	else {
		ret = pread_in_full(fd, &hdr, sizeof(hdr), 0);
		if (ret < 0)
			goto out;
	}

	//  check if the program is a HermitCore file
	if (hdr.e_ident[EI_MAG0] != ELFMAG0
	    || hdr.e_ident[EI_MAG1] != ELFMAG1
	    || hdr.e_ident[EI_MAG2] != ELFMAG2
	    || hdr.e_ident[EI_MAG3] != ELFMAG3
	    || hdr.e_ident[EI_CLASS] != ELFCLASS64
	    || hdr.e_ident[EI_OSABI] != HERMIT_ELFOSABI
	    || hdr.e_type != ET_EXEC || hdr.e_machine != EM_X86_64) {
		fprintf(stderr, "Inavlide HermitCore file!\n");
		goto out;
	}

	elf_entry = hdr.e_entry;

	buflen = hdr.e_phentsize * hdr.e_phnum;

	if(is_compressed)
		phdr = (Elf64_Phdr *)(compr_out + hdr.e_phoff);
	else {

		phdr = malloc(buflen);
		if (!phdr) {
			fprintf(stderr, "Not enough memory\n");
			goto out;
		}

		ret = pread_in_full(fd, phdr, buflen, hdr.e_phoff);
		if (ret < 0)
			goto out;
	}

	/*
	 * Load all segments with type "LOAD" from the file at offset
	 * p_offset, and copy that into in memory.
	 */
	for (Elf64_Half ph_i = 0; ph_i < hdr.e_phnum; ph_i++)
	{
		uint64_t paddr = phdr[ph_i].p_paddr;
		size_t offset = phdr[ph_i].p_offset;
		size_t filesz = phdr[ph_i].p_filesz;
		size_t memsz = phdr[ph_i].p_memsz;

		if (phdr[ph_i].p_type != PT_LOAD)
			continue;

		//printf("Kernel location 0x%zx, file size 0x%zx, memory size 0x%zx\n", paddr, filesz, memsz);

		if(is_compressed)
			memcpy(mem+paddr-GUEST_OFFSET, compr_out+offset, filesz);
		else {
			ret = pread_in_full(fd, mem+paddr-GUEST_OFFSET, filesz, offset);
			if (ret < 0)
				goto out;
		}

		if (!klog)
			klog = mem+paddr+0x5000-GUEST_OFFSET;
		if (!mboot)
			mboot = mem+paddr-GUEST_OFFSET;

		if (first_load) {
			first_load = 0;

			// initialize kernel
			*((uint64_t*) (mem+paddr-GUEST_OFFSET + 0x08)) = paddr; // physical start address
			*((uint64_t*) (mem+paddr-GUEST_OFFSET + 0x10)) = guest_size;   // physical limit
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x18)) = get_cpufreq();
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x24)) = 1; // number of used cpus
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x30)) = 0; // apicid
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x60)) = 1; // numa nodes
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x94)) = 1; // announce uhyve


			char* str = getenv("HERMIT_IP");
			if (str) {
				uint32_t ip[4];

				sscanf(str, "%u.%u.%u.%u",	ip+0, ip+1, ip+2, ip+3);
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB0)) = (uint8_t) ip[0];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB1)) = (uint8_t) ip[1];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB2)) = (uint8_t) ip[2];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB3)) = (uint8_t) ip[3];
			}

			str = getenv("HERMIT_GATEWAY");
			if (str) {
				uint32_t ip[4];

				sscanf(str, "%u.%u.%u.%u",	ip+0, ip+1, ip+2, ip+3);
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB4)) = (uint8_t) ip[0];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB5)) = (uint8_t) ip[1];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB6)) = (uint8_t) ip[2];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB7)) = (uint8_t) ip[3];
			}

			str = getenv("HERMIT_MASK");
			if (str) {
				uint32_t ip[4];

				sscanf(str, "%u.%u.%u.%u",	ip+0, ip+1, ip+2, ip+3);
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB8)) = (uint8_t) ip[0];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB9)) = (uint8_t) ip[1];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xBA)) = (uint8_t) ip[2];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xBB)) = (uint8_t) ip[3];
			}
		}
		total_size += memsz; // total kernel size
		*((uint64_t*) (mem+paddr-GUEST_OFFSET + 0x38)) = total_size;

		/* Enable minifs or not */
		char *str = getenv("HERMIT_MINIFS");
		if(str && atoi(str))
			*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xE1)) = (uint8_t)1;

	}

out:
	if (phdr && !is_compressed)
		free(phdr);

	if(is_compressed) {
		free(compr_in);
		free(compr_out);
	}

	if(!is_compressed)
		close(fd);

	//if (verbose)
	//	fprintf(stderr, "Memory size of the image: %zd KiB\n", total_size / 1024);

	return 0;
}

static int load_checkpoint(uint8_t* mem, const char* path)
{
	char fname[MAX_FNAME];
	size_t location;
	size_t paddr = elf_entry;
	int ret;
	struct timeval begin, end;
	uint32_t i;

	if (verbose)
		gettimeofday(&begin, NULL);

	if (!klog)
		klog = mem+paddr+0x5000-GUEST_OFFSET;
	if (!mboot)
		mboot = mem+paddr-GUEST_OFFSET;


#ifdef USE_DIRTY_LOG
	/*
	 * if we use KVM's dirty page logging, we have to load
	 * the elf image because most parts are readonly sections
	 * and aren't able to detect by KVM's dirty page logging
	 * technique.
	 */
	const char* hermit_tux;

	ret = load_kernel(mem, path);
	if (ret)
		return ret;

	hermit_tux = getenv("HERMIT_TUX");
	if (hermit_tux)
	{
		if (htux_bin == NULL) {
			fprintf(stderr, "Name of the ELF file is missing!\n");
			exit(EXIT_FAILURE);
		}

		if (uhyve_elf_loader(htux_bin) < 0)
			exit(EXIT_FAILURE);
	}

#endif

	i = full_checkpoint ? no_checkpoint : 0;
	for(; i<=no_checkpoint; i++)
	{
		snprintf(fname, MAX_FNAME, "checkpoint/chk%u_mem.dat", i);

		FILE* f = fopen(fname, "r");
		if (f == NULL)
			return -1;

		/*struct kvm_irqchip irqchip;
		if (fread(&irqchip, sizeof(irqchip), 1, f) != 1)
			err(1, "fread failed");
		if (cap_irqchip && (i == no_checkpoint-1))
			kvm_ioctl(vmfd, KVM_SET_IRQCHIP, &irqchip);*/

		struct kvm_clock_data clock;
		if (fread(&clock, sizeof(clock), 1, f) != 1)
			err(1, "fread failed");
		// only the last checkpoint has to set the clock
		if (cap_adjust_clock_stable && (i == no_checkpoint)) {
			struct kvm_clock_data data = {};

			data.clock = clock.clock;
			kvm_ioctl(vmfd, KVM_SET_CLOCK, &data);
		}

#if 0
		if (fread(guest_mem, guest_size, 1, f) != 1)
			err(1, "fread failed");
#else

		while (fread(&location, sizeof(location), 1, f) == 1) {
			//printf("location 0x%zx\n", location);
			if (location & PG_PSE)
				ret = fread((size_t*) (mem + (location & PAGE_2M_MASK)), (1UL << PAGE_2M_BITS), 1, f);
			else
				ret = fread((size_t*) (mem + (location & PAGE_MASK)), (1UL << PAGE_BITS), 1, f);

			if (ret != 1) {
				fprintf(stderr, "Unable to read checkpoint: ret = %d", ret);
				err(1, "fread failed");
			}
		}
#endif

		fclose(f);
	}

	if (verbose) {
		gettimeofday(&end, NULL);
		size_t msec = (end.tv_sec - begin.tv_sec) * 1000;
		msec += (end.tv_usec - begin.tv_usec) / 1000;
		fprintf(stderr, "Load checkpoint %u in %zd ms\n", no_checkpoint, msec);
	}

	return 0;
}

static inline void show_dtable(const char *name, struct kvm_dtable *dtable)
{
	fprintf(stderr, " %s                 %016zx  %08hx\n", name, (size_t) dtable->base, (uint16_t) dtable->limit);
}

static inline void show_segment(const char *name, struct kvm_segment *seg)
{
	fprintf(stderr, " %s       %04hx      %016zx  %08x  %02hhx    %x %x   %x  %x %x %x %x\n",
		name, (uint16_t) seg->selector, (size_t) seg->base, (uint32_t) seg->limit,
		(uint8_t) seg->type, seg->present, seg->dpl, seg->db, seg->s, seg->l, seg->g, seg->avl);
}

static void show_registers(int id, struct kvm_regs* regs, struct kvm_sregs* sregs)
{
	size_t cr0, cr2, cr3;
	size_t cr4, cr8;
	size_t rax, rbx, rcx;
	size_t rdx, rsi, rdi;
	size_t rbp,  r8,  r9;
	size_t r10, r11, r12;
	size_t r13, r14, r15;
	size_t rip, rsp;
	size_t rflags;
	int i;

	rflags = regs->rflags;
	rip = regs->rip; rsp = regs->rsp;
	rax = regs->rax; rbx = regs->rbx; rcx = regs->rcx;
	rdx = regs->rdx; rsi = regs->rsi; rdi = regs->rdi;
	rbp = regs->rbp; r8  = regs->r8;  r9  = regs->r9;
	r10 = regs->r10; r11 = regs->r11; r12 = regs->r12;
	r13 = regs->r13; r14 = regs->r14; r15 = regs->r15;

	fprintf(stderr, "\n Dump state of CPU %d\n", id);
	fprintf(stderr, "\n Registers:\n");
	fprintf(stderr, " ----------\n");
	fprintf(stderr, " rip: %016zx   rsp: %016zx flags: %016zx\n", rip, rsp, rflags);
	fprintf(stderr, " rax: %016zx   rbx: %016zx   rcx: %016zx\n", rax, rbx, rcx);
	fprintf(stderr, " rdx: %016zx   rsi: %016zx   rdi: %016zx\n", rdx, rsi, rdi);
	fprintf(stderr, " rbp: %016zx    r8: %016zx    r9: %016zx\n", rbp, r8,  r9);
	fprintf(stderr, " r10: %016zx   r11: %016zx   r12: %016zx\n", r10, r11, r12);
	fprintf(stderr, " r13: %016zx   r14: %016zx   r15: %016zx\n", r13, r14, r15);

	cr0 = sregs->cr0; cr2 = sregs->cr2; cr3 = sregs->cr3;
	cr4 = sregs->cr4; cr8 = sregs->cr8;

	fprintf(stderr, " cr0: %016zx   cr2: %016zx   cr3: %016zx\n", cr0, cr2, cr3);
	fprintf(stderr, " cr4: %016zx   cr8: %016zx\n", cr4, cr8);
	fprintf(stderr, "\n Segment registers:\n");
	fprintf(stderr,   " ------------------\n");
	fprintf(stderr, " register  selector  base              limit     type  p dpl db s l g avl\n");
	show_segment("cs ", &sregs->cs);
	show_segment("ss ", &sregs->ss);
	show_segment("ds ", &sregs->ds);
	show_segment("es ", &sregs->es);
	show_segment("fs ", &sregs->fs);
	show_segment("gs ", &sregs->gs);
	show_segment("tr ", &sregs->tr);
	show_segment("ldt", &sregs->ldt);
	show_dtable("gdt", &sregs->gdt);
	show_dtable("idt", &sregs->idt);

	fprintf(stderr, "\n APIC:\n");
	fprintf(stderr,   " -----\n");
	fprintf(stderr, " efer: %016zx  apic base: %016zx\n",
		(size_t) sregs->efer, (size_t) sregs->apic_base);

	fprintf(stderr, "\n Interrupt bitmap:\n");
	fprintf(stderr,   " -----------------\n");
	for (i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++)
		fprintf(stderr, " %016zx", (size_t) sregs->interrupt_bitmap[i]);
	fprintf(stderr, "\n");
}

static void print_registers(void)
{
	struct kvm_regs regs;
	struct kvm_sregs sregs;

	kvm_ioctl(vcpufd, KVM_GET_SREGS, &sregs);
	kvm_ioctl(vcpufd, KVM_GET_REGS, &regs);

	show_registers(cpuid, &regs, &sregs);
}

/// Filter CPUID functions that are not supported by the hypervisor and enable
/// features according to our needs.
static void filter_cpuid(struct kvm_cpuid2 *kvm_cpuid)
{
	for (uint32_t i = 0; i < kvm_cpuid->nent; i++) {
		struct kvm_cpuid_entry2 *entry = &kvm_cpuid->entries[i];

		switch (entry->function) {
		case 1:
			// CPUID to define basic cpu features
			entry->ecx |= (1U << 31); // propagate that we are running on a hypervisor
			if (cap_tsc_deadline)
				entry->ecx |= (1U << 24); // enable TSC deadline feature
			entry->edx |= (1U <<  5); // enable msr support
			break;

		case CPUID_FUNC_PERFMON:
			// disable it
			entry->eax	= 0x00;
			break;

		default:
			// Keep the CPUID function as-is
			break;
		};
	}
}

static void setup_system_64bit(struct kvm_sregs *sregs)
{
	sregs->cr0 |= X86_CR0_PE;
	sregs->efer |= EFER_LME | EFER_LMA;
}

static void setup_system_page_tables(struct kvm_sregs *sregs, uint8_t *mem)
{
	uint64_t *pml4 = (uint64_t *) (mem + BOOT_PML4);
	uint64_t *pdpte = (uint64_t *) (mem + BOOT_PDPTE);
	uint64_t *pde = (uint64_t *) (mem + BOOT_PDE);
	uint64_t paddr;

	/*
	 * For simplicity we currently use 2MB pages and only a single
	 * PML4/PDPTE/PDE.
	 */

	memset(pml4, 0x00, 4096);
	memset(pdpte, 0x00, 4096);
	memset(pde, 0x00, 4096);

	*pml4 = BOOT_PDPTE | (X86_PDPT_P | X86_PDPT_RW);
	*pdpte = BOOT_PDE | (X86_PDPT_P | X86_PDPT_RW);
	for (paddr = 0; paddr < 0x20000000ULL; paddr += GUEST_PAGE_SIZE, pde++)
		*pde = paddr | (X86_PDPT_P | X86_PDPT_RW | X86_PDPT_PS);

	sregs->cr3 = BOOT_PML4;
	sregs->cr4 |= X86_CR4_PAE;
	sregs->cr0 |= X86_CR0_PG;
}

static void setup_system_gdt(struct kvm_sregs *sregs,
                             uint8_t *mem,
                             uint64_t off)
{
	uint64_t *gdt = (uint64_t *) (mem + off);
	struct kvm_segment data_seg, code_seg;

	/* flags, base, limit */
	gdt[BOOT_GDT_NULL] = GDT_ENTRY(0, 0, 0);
	gdt[BOOT_GDT_CODE] = GDT_ENTRY(0xA09B, 0, 0xFFFFF);
	gdt[BOOT_GDT_DATA] = GDT_ENTRY(0xC093, 0, 0xFFFFF);

	sregs->gdt.base = off;
	sregs->gdt.limit = (sizeof(uint64_t) * BOOT_GDT_MAX) - 1;

	GDT_TO_KVM_SEGMENT(code_seg, gdt, BOOT_GDT_CODE);
	GDT_TO_KVM_SEGMENT(data_seg, gdt, BOOT_GDT_DATA);

	sregs->cs = code_seg;
	sregs->ds = data_seg;
	sregs->es = data_seg;
	sregs->fs = data_seg;
	sregs->gs = data_seg;
	sregs->ss = data_seg;
}

static void setup_system(int vcpufd, uint8_t *mem, uint32_t id)
{
	static struct kvm_sregs sregs;

	// all cores use the same startup code
	// => all cores use the same sregs
	// => only the boot processor has to initialize sregs
	if (id == 0) {
		kvm_ioctl(vcpufd, KVM_GET_SREGS, &sregs);

		/* Set all cpu/mem system structures */
		setup_system_gdt(&sregs, mem, BOOT_GDT);
		setup_system_page_tables(&sregs, mem);
		setup_system_64bit(&sregs);
	}

	kvm_ioctl(vcpufd, KVM_SET_SREGS, &sregs);
}

static void setup_cpuid(int kvm, int vcpufd)
{
	struct kvm_cpuid2 *kvm_cpuid;
	unsigned int max_entries = 100;

	// allocate space for cpuid we get from KVM
	kvm_cpuid = calloc(1, sizeof(*kvm_cpuid) + (max_entries * sizeof(kvm_cpuid->entries[0])));
	kvm_cpuid->nent = max_entries;

	kvm_ioctl(kvm, KVM_GET_SUPPORTED_CPUID, kvm_cpuid);

	// set features
	filter_cpuid(kvm_cpuid);
	kvm_ioctl(vcpufd, KVM_SET_CPUID2, kvm_cpuid);

	free(kvm_cpuid);
}

static void* wait_for_packet(void* arg)
{
	int ret;
	struct pollfd fds = {	.fd = netfd,
							.events = POLLIN,
							.revents  = 0};

	usleep(30000);
	while(1)
	{
		fds.revents = 0;

		ret = poll(&fds, 1, -1000);

		if (ret < 0 && errno == EINTR)
			continue;

		if (ret < 0)
			perror("poll()");
		else if (ret) {
			uint64_t event_counter = 1;
			write(efd, &event_counter, sizeof(event_counter));
			sem_wait(&net_sem);
		}
	}

	return NULL;
}

static inline void check_network(void)
{
	// should we start the network thread?
	if ((efd < 0) && (getenv("HERMIT_NETIF"))) {
		struct kvm_irqfd irqfd = {};

		efd = eventfd(0, 0);
		irqfd.fd = efd;
		irqfd.gsi = UHYVE_IRQ;
		kvm_ioctl(vmfd, KVM_IRQFD, &irqfd);

		sem_init(&net_sem, 0, 0);

		if (pthread_create(&net_thread, NULL, wait_for_packet, NULL))
			err(1, "unable to create thread");
	}
}

static int vcpu_loop(void)
{
	int ret;

	/* Try to determine the smallest fd value the guest can use, assume they
	 * are given sequentially by the kernel */
	int min_guest_fd = open("/tmp", O_RDONLY, 0x0);
	if(min_guest_fd != -1) {
		close(min_guest_fd);
	} else {
		/* for now at least let's not let app close stdin/out/err */
		min_guest_fd = 2;
	}

	if (restart) {
		pthread_barrier_wait(&barrier);
		if (cpuid == 0)
			no_checkpoint++;
	}

	if (verbose)
		puts("uhyve is entering vcpu_loop");

	while (1) {
		ret = ioctl(vcpufd, KVM_RUN, NULL);

		if(ret == -1) {
			switch(errno) {
			case EINTR:
				continue;

			case EFAULT: {
				struct kvm_regs regs;
				kvm_ioctl(vcpufd, KVM_GET_REGS, &regs);
				err(1, "KVM: host/guest translation fault: rip=0x%llx", regs.rip);
			}

			default:
				err(1, "KVM: ioctl KVM_RUN in vcpu_loop failed");
				break;
			}
		}

		/* handle requests */
		switch (run->exit_reason) {
		case KVM_EXIT_HLT:
			fprintf(stderr, "Guest has halted the CPU, this is considered as a normal exit.\n");
			if(uhyve_gdb_enabled)
				uhyve_gdb_handle_term();
			return 0;

		case KVM_EXIT_MMIO:
			err(1, "KVM: unhandled KVM_EXIT_MMIO at 0x%llx\n", run->mmio.phys_addr);
			break;

		case KVM_EXIT_IO:
			//printf("port 0x%x\n", run->io.port);
			switch (run->io.port) {
			case UHYVE_PORT_WRITE: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_write_t* uhyve_write = (uhyve_write_t*) (guest_mem+data);

				ret = write(uhyve_write->fd, guest_mem+(size_t)uhyve_write->buf, uhyve_write->len);
				if(ret == -1)
					uhyve_write->ret = -errno;
				else
					uhyve_write->ret = ret;
				break;
				}

			case UHYVE_PORT_READ: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_read_t* uhyve_read = (uhyve_read_t*) (guest_mem+data);

				ret = read(uhyve_read->fd, guest_mem+(size_t)uhyve_read->buf, uhyve_read->len);
				if(ret == -1)
					uhyve_read->ret = -errno;
				else
					uhyve_read->ret = ret;
				break;
				}

			case UHYVE_PORT_EXIT: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));

					if (cpuid)
						pthread_exit((int*)(guest_mem+data));
					else {
						exit(*(int*)(guest_mem+data));
					}
					break;
				}

			case UHYVE_PORT_OPEN: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_open_t* uhyve_open = (uhyve_open_t*) (guest_mem+data);

				ret = open((const char*)guest_mem+(size_t)uhyve_open->name, uhyve_open->flags, uhyve_open->mode);

				/* With seccomp filter on, /dev/kvm is the only sensible thing
				 * that we import from the host in the sandbox, let's make sure
				 * it is never opened by the guest */
				if(uhyve_seccomp_enabled) {
					char *rval;
					char abspath[128];
					const char *filename = (const char *)guest_mem+(size_t)uhyve_open->name;

					rval = realpath(filename, abspath);
					if(rval && !strcmp(abspath, "/dev/kvm")) {
						fprintf(stderr, "guest tries to access /dev/kvm\n");
						exit(-1);
					}
				}


				if(ret == -1)
					uhyve_open->ret = -errno;
				else
					uhyve_open->ret = ret;
					break;
				}

			case UHYVE_PORT_UNLINK: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_unlink_t *uhyve_unlink = (uhyve_unlink_t *) (guest_mem+data);

				uhyve_unlink->ret =
				ret = unlink((const char *)guest_mem+(size_t)uhyve_unlink->pathname);
				if(ret == -1)
					uhyve_unlink->ret = -errno;
				else
					uhyve_unlink->ret = ret;
					break;
				}

			case UHYVE_PORT_MKDIR: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_mkdir_t *uhyve_mkdir = (uhyve_mkdir_t *) (guest_mem+data);

				ret = mkdir((const char *)(guest_mem+(size_t)uhyve_mkdir->pathname), uhyve_mkdir->mode);
				uhyve_mkdir->ret = (ret == -1) ? -errno : ret;
					break;

			}

			case UHYVE_PORT_RMDIR: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_rmdir_t *uhyve_rmdir = (uhyve_rmdir_t *) (guest_mem+data);

				ret = rmdir((const char *)(guest_mem+(size_t)uhyve_rmdir->pathname));
				uhyve_rmdir->ret = (ret == -1) ? -errno : ret;
				break;
			}

			case UHYVE_PORT_FSTAT: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_fstat_t *uhyve_fstat = (uhyve_fstat_t *) (guest_mem+data);

				ret = fstat(uhyve_fstat->fd, (struct stat *)(guest_mem+(size_t)uhyve_fstat->st));

				uhyve_fstat->ret = (ret == -1) ? -errno : ret;
					break;
				}

			case UHYVE_PORT_GETCWD: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_getcwd_t *uhyve_getcwd = (uhyve_getcwd_t *) (guest_mem+data);

				getcwd((char *)(guest_mem+(size_t)uhyve_getcwd->buf), uhyve_getcwd->size);
				break;
			}

			case UHYVE_PORT_CLOSE: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_close_t* uhyve_close = (uhyve_close_t*) (guest_mem+data);

				if (uhyve_close->fd >= min_guest_fd) {
					ret = close(uhyve_close->fd);
					uhyve_close->ret = (ret == -1) ? -errno : ret;
                } else if (uhyve_close->fd <= 2) {
                    /* fake success for closing stdin/stdout/stderr */
					uhyve_close->ret = 0;
                } else {
                    /* internal uhyve fds for KVM VM and vCPUs! */
                    uhyve_close->ret = -EBADF;
                }
				break;
			}

			case UHYVE_PORT_GETDENTS64: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_getdeents64_t* arg = (uhyve_getdeents64_t*) (guest_mem+data);

				arg->ret = syscall(SYS_getdents64, arg->fd,
						guest_mem+(size_t)arg->dirp, arg->count);
				break;
				}

			case UHYVE_PORT_GETDENTS: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_getdeents_t* arg = (uhyve_getdeents_t*) (guest_mem+data);

				arg->ret = syscall(SYS_getdents, arg->fd,
						guest_mem+(size_t)arg->dirp, arg->count);
				break;
				}

			case UHYVE_PORT_FCNTL: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_fcntl_t* arg = (uhyve_fcntl_t*) (guest_mem+data);

				arg->ret = fcntl(arg->fd, arg->cmd, arg->arg);
				break;
				}

			case UHYVE_PORT_OPENAT: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_openat_t* arg = (uhyve_openat_t*) (guest_mem+data);

				arg->ret = openat(arg->dirfd, guest_mem+(size_t)arg->name,
						arg->flags,	arg->mode);
				break;
				}

			case UHYVE_PORT_NETINFO: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_netinfo_t* uhyve_netinfo = (uhyve_netinfo_t*)(guest_mem+data);
					memcpy(uhyve_netinfo->mac_str, uhyve_get_mac(), 18);
					// guest configure the ethernet device => start network thread
					check_network();
					break;
				}

			case UHYVE_PORT_NETWRITE: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_netwrite_t* uhyve_netwrite = (uhyve_netwrite_t*)(guest_mem + data);
					uhyve_netwrite->ret = 0;
					ret = write(netfd, guest_mem + (size_t)uhyve_netwrite->data, uhyve_netwrite->len);
					if (ret >= 0) {
						uhyve_netwrite->ret = 0;
						uhyve_netwrite->len = ret;
					} else {
						uhyve_netwrite->ret = -1;
					}
					break;
				}

			case UHYVE_PORT_NETREAD: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_netread_t* uhyve_netread = (uhyve_netread_t*)(guest_mem + data);
					ret = read(netfd, guest_mem + (size_t)uhyve_netread->data, uhyve_netread->len);
					if (ret > 0) {
						uhyve_netread->len = ret;
						uhyve_netread->ret = 0;
					} else {
						uhyve_netread->ret = -1;
						sem_post(&net_sem);
					}
					break;
				}

			case UHYVE_PORT_NETSTAT: {
					unsigned status = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_netstat_t* uhyve_netstat = (uhyve_netstat_t*)(guest_mem + status);
					char* str = getenv("HERMIT_NETIF");
					if (str)
						uhyve_netstat->status = 1;
					else
						uhyve_netstat->status = 0;
					break;
				}

			case UHYVE_PORT_LSEEK: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_lseek_t* uhyve_lseek = (uhyve_lseek_t*) (guest_mem+data);

					uhyve_lseek->offset = lseek(uhyve_lseek->fd, uhyve_lseek->offset, uhyve_lseek->whence);
					break;
				}

			case UHYVE_PORT_ACCESS: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_access_t *uhyve_access = (uhyve_access_t*) (guest_mem+data);

					uhyve_access->ret = access((char *)guest_mem+(size_t)uhyve_access->pathname,
							uhyve_access->mode);
					break;
				}

			case UHYVE_PORT_CMDSIZE: {
					int i;
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_cmdsize_t *val = (uhyve_cmdsize_t *) (guest_mem+data);

					val->argc = uhyve_argc;
					for(i=0; i<uhyve_argc; i++)
						val->argsz[i] = strlen(uhyve_argv[i]) + 1;

					val->envc = uhyve_envc;
					for(i=0; i<uhyve_envc; i++)
						val->envsz[i] = strlen(uhyve_envp[i]) + 1;

					break;
				}

			case UHYVE_PORT_CMDVAL: {
					int i;
					char **argv_ptr, **env_ptr;
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_cmdval_t *val = (uhyve_cmdval_t *) (guest_mem+data);

					/* argv */
					argv_ptr = (char **)(guest_mem + (size_t)val->argv);
					for(i=0; i<uhyve_argc; i++)
						strcpy(guest_mem + (size_t)argv_ptr[i], uhyve_argv[i]);

					/* env */
					env_ptr = (char **)(guest_mem + (size_t)val->envp);
					for(i=0; i<uhyve_envc; i++)
						strcpy(guest_mem + (size_t)env_ptr[i], uhyve_envp[i]);

					break;
				}

			case UHYVE_PORT_PFAULT: {
				char addr2line_call[128];
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_pfault_t *arg = (uhyve_pfault_t *)(guest_mem + data);
				fprintf(stderr, "GUEST PAGE FAULT @0x%llx (RIP @0x%llx)\n",
						arg->addr, arg->rip);
				sprintf(addr2line_call, "addr2line -a %llx -e %s\n", arg->rip,
						(arg->rip >= tux_start_address) ? htux_bin :
						htux_kernel);
				system(addr2line_call);

				break;
				}

			case UHYVE_PORT_FAULT: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_fault_t *arg = (uhyve_fault_t *)(guest_mem + data);

				fprintf(stderr, "GUEST EXCEPTION %u (RIP @0x%x)\n", arg->int_no,
						arg->rip);

				break;
				}

			case UHYVE_PORT_READLINK: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_readlink_t *arg = (uhyve_readlink_t *)(guest_mem + data);

				/* many programs access the application binary not through
				 * argv[0] but through /proc/self/exec, for us it is actually
				 * proxy so we need to correct that */
				if(!strcmp(guest_mem+(size_t)arg->path, "/proc/self/exe")) {
					char abspath[256];
					realpath(htux_bin, abspath);

					if(arg->bufsz > strlen(abspath)) {
						strcpy(guest_mem+(size_t)arg->buf, abspath);
						arg->ret = strlen(abspath);
					}
					else
						arg->ret = -1;

					break;

				}

				ret = readlink(guest_mem+(size_t)arg->path,
						guest_mem+(size_t)arg->buf, arg->bufsz);

				arg->ret = (ret == -1) ? -errno : ret;
				break;
				}

			/* When using minifs, we can load some files from the host, in that
			 * case the env. varian;e HERMIT_MINIFS_HOSTLOAD must be set with
			 * a path to a 'listing' file that has one line per file to laod
			 * from the host into the guest minifs, with the following format:
			 * <source file on the host>;<target path on the guest> */
			case UHYVE_PORT_MINIFS_LOAD: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_minifs_load_t *arg = (uhyve_minifs_load_t *)(guest_mem + data);
				static FILE *minifs_fp = NULL;
				size_t len, bytes_read = 0;
				char *line = NULL;
				char *filename = getenv("HERMIT_MINIFS_HOSTLOAD");

				if(!minifs_fp) {
					if(filename)
						minifs_fp = fopen(filename, "r");

					if(!minifs_fp) {
						/* Could not open the listing ile, or no listing file
						 * provided, we indicate to the guest that we're done */
						arg->hostpath[0] = arg->guestpath[0] = '\0';
						break;
					}
				}

				/* Comments in this file are lines starting with '#' */
				do
					bytes_read = getline(&line, &len, minifs_fp);
				while (line[0] == '#' && bytes_read != -1);

				if(bytes_read == -1) {
					/* End of file, we are done */
					arg->hostpath[0] = arg->guestpath[0] = '\0';
					fclose(minifs_fp);
					break;
				} else {
					int guestpath_offset, i = 0;

					/* Set the host path */
					while(line[i] != ';') {
						if(i >= MINIFS_LOAD_MAXPATH) {
							fprintf(stderr, "minifs load from %s: % too long\n",
									filename, "hostpath");
							arg->hostpath[0] = arg->guestpath[0] = '\0';
							break;
						}

						arg->hostpath[i] = line[i];
						i++;
					}

					/* Set the guest path */
					arg->hostpath[i++] = '\0';
					guestpath_offset = i;
					while(line[i] != '\n') {
						if((i-guestpath_offset) >= MINIFS_LOAD_MAXPATH) {
							fprintf(stderr, "minifs load from %s: % too long\n",
									filename, "hostpath");
							arg->hostpath[0] = arg->guestpath[0] = '\0';
							break;
						}

						arg->guestpath[i-guestpath_offset] = line[i];
						i++;
					}
					arg->guestpath[i-guestpath_offset] = '\0';
				}

				break;
			}

			case UHYVE_PORT_CREAT: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_creat_t *arg = (uhyve_creat_t *)(guest_mem + data);

				int ret = creat((const char *)(guest_mem+(size_t)arg->path),
						arg->mode);

				if(ret == -1)
					arg->ret = -errno;
				else
					arg->ret = ret;

				break;
			}
			case UHYVE_PORT_RENAME: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_rename_t *arg = (uhyve_rename_t *)(guest_mem + data);

				int ret = rename((const char *)(guest_mem+(size_t)arg->oldpath),
						(const char *)(guest_mem+(size_t)arg->newpath));

				if(ret == -1)
					arg->ret = -errno;
				else
					arg->ret = ret;

				break;
			}

			case UHYVE_PORT_TRUNCATE : {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_truncate_t *arg = (uhyve_truncate_t *)(guest_mem + data);

				int ret = truncate((const char *)(guest_mem+(size_t)arg->path),
						arg->length);

				if(ret == -1)
					arg->ret = -errno;
				else
					arg->ret = ret;

				break;
			}

			case UHYVE_PORT_FTRUNCATE : {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_ftruncate_t *arg = (uhyve_ftruncate_t *)(guest_mem + data);

				int ret = ftruncate(arg->fd, arg->length);

				if(ret == -1)
					arg->ret = -errno;
				else
					arg->ret = ret;

				break;
			}

			case UHYVE_PORT_SYNC:
			case UHYVE_PORT_FSYNC:
			case UHYVE_PORT_FDATASYNC:
			case UHYVE_PORT_SYNCFS: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_fsync_t *arg = (uhyve_fsync_t *)(guest_mem + data);

				if(run->io.port == UHYVE_PORT_SYNC)
					sync();
				else if(run->io.port == UHYVE_PORT_SYNCFS)
					arg->ret = syncfs(arg->fd);
				else if(run->io.port == UHYVE_PORT_FSYNC)
					arg->ret = fsync(arg->fd);
				else if(run->io.port == UHYVE_PORT_FDATASYNC)
					arg->ret = fdatasync(arg->fd);

				break;
			}

			case UHYVE_PORT_DUP2: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_dup2_t *arg = (uhyve_dup2_t *)(guest_mem + data);

				arg->ret = dup2(arg->oldfd, arg->newfd);
				break;
			}

            case UHYVE_PORT_PIPE: {
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_pipe_t *arg = (uhyve_pipe_t *)(guest_mem + data);

				arg->ret = pipe(arg->filedes);
				break;
			}

			case UHYVE_PORT_NEWFSTATAT: {
				int ret;
				unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
				uhyve_newfstatat_t *args = (uhyve_newfstatat_t *) (guest_mem+data);

				ret = syscall(SYS_newfstatat, args->dirfd,
                        (const char *)(guest_mem+(size_t)args->name),
                        (struct stat *)(guest_mem+(size_t)args->st),
                        args->flag);

				args->ret = (ret == -1) ? -errno : ret;
					break;
				}

			default:
				err(1, "KVM: unhandled KVM_EXIT_IO at port 0x%x, direction %d\n", run->io.port, run->io.direction);
				break;
			}
			break;

		case KVM_EXIT_FAIL_ENTRY:
			if(uhyve_gdb_enabled)
				uhyve_gdb_handle_exception(vcpufd, GDB_SIGNAL_SEGV);
			err(1, "KVM: entry failure: hw_entry_failure_reason=0x%llx\n",
				run->fail_entry.hardware_entry_failure_reason);
			break;

		case KVM_EXIT_INTERNAL_ERROR:
			if(uhyve_gdb_enabled)
				uhyve_gdb_handle_exception(vcpufd, GDB_SIGNAL_SEGV);
			err(1, "KVM: internal error exit: suberror = 0x%x\n", run->internal.suberror);
			break;

		case KVM_EXIT_SHUTDOWN:
			err(1, "KVM: receive shutdown command\n");
			break;

		case KVM_EXIT_DEBUG:
			if(uhyve_gdb_enabled) {
				uhyve_gdb_handle_exception(vcpufd, GDB_SIGNAL_TRAP);
				break;
			}
			else
				print_registers();
		default:
			fprintf(stderr, "KVM: unhandled exit: exit_reason = 0x%x\n", run->exit_reason);
			exit(EXIT_FAILURE);
		}
	}

	close(vcpufd);
	vcpufd = -1;

	return 0;
}

static int vcpu_init(void)
{
	struct kvm_mp_state mp_state = { KVM_MP_STATE_RUNNABLE };
	struct kvm_regs regs = {
		.rip = elf_entry,	// entry point to HermitCore
		.rflags = 0x2,		// POR value required by x86 architecture
	};

	vcpu_fds[cpuid] = vcpufd = kvm_ioctl(vmfd, KVM_CREATE_VCPU, cpuid);

	/* Map the shared kvm_run structure and following data. */
	size_t mmap_size = (size_t) kvm_ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);

	if (mmap_size < sizeof(*run))
		err(1, "KVM: invalid VCPU_MMAP_SIZE: %zd", mmap_size);

	run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
	if (run == MAP_FAILED)
		err(1, "KVM: VCPU mmap failed");

	run->apic_base = APIC_DEFAULT_BASE;
	setup_cpuid(kvm, vcpufd);

	if (restart) {
		char fname[MAX_FNAME];
		struct kvm_sregs sregs;
		struct kvm_fpu fpu;
		struct {
			struct kvm_msrs info;
			struct kvm_msr_entry entries[MAX_MSR_ENTRIES];
		} msr_data;
		struct kvm_lapic_state lapic;
		struct kvm_xsave xsave;
		struct kvm_xcrs xcrs;
		struct kvm_vcpu_events events;

		snprintf(fname, MAX_FNAME, "checkpoint/chk%u_core%u.dat", no_checkpoint, cpuid);

		FILE* f = fopen(fname, "r");
		if (f == NULL)
			err(1, "fopen: unable to open file");

		if (fread(&sregs, sizeof(sregs), 1, f) != 1)
			err(1, "fread failed\n");
		if (fread(&regs, sizeof(regs), 1, f) != 1)
			err(1, "fread failed\n");
		if (fread(&fpu, sizeof(fpu), 1, f) != 1)
			err(1, "fread failed\n");
		if (fread(&msr_data, sizeof(msr_data), 1, f) != 1)
			err(1, "fread failed\n");
		if (fread(&lapic, sizeof(lapic), 1, f) != 1)
			err(1, "fread failed\n");
		if (fread(&xsave, sizeof(xsave), 1, f) != 1)
			err(1, "fread failed\n");
		if (fread(&xcrs, sizeof(xcrs), 1, f) != 1)
			err(1, "fread failed\n");
		if (fread(&events, sizeof(events), 1, f) != 1)
			err(1, "fread failed\n");
		if (fread(&mp_state, sizeof(mp_state), 1, f) != 1)
			err(1, "fread failed\n");

		fclose(f);

		kvm_ioctl(vcpufd, KVM_SET_SREGS, &sregs);
		kvm_ioctl(vcpufd, KVM_SET_REGS, &regs);
		kvm_ioctl(vcpufd, KVM_SET_MSRS, &msr_data);
		kvm_ioctl(vcpufd, KVM_SET_XCRS, &xcrs);
		kvm_ioctl(vcpufd, KVM_SET_MP_STATE, &mp_state);
		kvm_ioctl(vcpufd, KVM_SET_LAPIC, &lapic);
		kvm_ioctl(vcpufd, KVM_SET_FPU, &fpu);
		kvm_ioctl(vcpufd, KVM_SET_XSAVE, &xsave);
		kvm_ioctl(vcpufd, KVM_SET_VCPU_EVENTS, &events);
	} else {
		struct {
			struct kvm_msrs info;
			struct kvm_msr_entry entries[MAX_MSR_ENTRIES];
		} msr_data;
		struct kvm_msr_entry *msrs = msr_data.entries;

		// be sure that the multiprocessor is runable
		kvm_ioctl(vcpufd, KVM_SET_MP_STATE, &mp_state);

		// enable fast string operations
		msrs[0].index = MSR_IA32_MISC_ENABLE;
		msrs[0].data = 1;
		msr_data.info.nmsrs = 1;
		kvm_ioctl(vcpufd, KVM_SET_MSRS, &msr_data);

		/* Setup registers and memory. */
		setup_system(vcpufd, guest_mem, cpuid);

		kvm_ioctl(vcpufd, KVM_SET_REGS, &regs);

		// only one core is able to enter startup code
		// => the wait for the predecessor core
		while (*((volatile uint32_t*) (mboot + 0x20)) < cpuid)
			pthread_yield();
		*((volatile uint32_t*) (mboot + 0x30)) = cpuid;
	}

	return 0;
}

static void save_cpu_state(void)
{
	struct {
		struct kvm_msrs info;
		struct kvm_msr_entry entries[MAX_MSR_ENTRIES];
	} msr_data;
	struct kvm_msr_entry *msrs = msr_data.entries;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_fpu fpu;
	struct kvm_lapic_state lapic;
	struct kvm_xsave xsave;
	struct kvm_xcrs xcrs;
	struct kvm_vcpu_events events;
	struct kvm_mp_state mp_state;
	char fname[MAX_FNAME];
	int n = 0;

	/* define the list of required MSRs */
	msrs[n++].index = MSR_IA32_APICBASE;
	msrs[n++].index = MSR_IA32_SYSENTER_CS;
	msrs[n++].index = MSR_IA32_SYSENTER_ESP;
	msrs[n++].index = MSR_IA32_SYSENTER_EIP;
	msrs[n++].index = MSR_IA32_CR_PAT;
	msrs[n++].index = MSR_IA32_MISC_ENABLE;
	msrs[n++].index = MSR_IA32_TSC;
	msrs[n++].index = MSR_CSTAR;
	msrs[n++].index = MSR_STAR;
	msrs[n++].index = MSR_EFER;
	msrs[n++].index = MSR_LSTAR;
	msrs[n++].index = MSR_GS_BASE;
	msrs[n++].index = MSR_FS_BASE;
	msrs[n++].index = MSR_KERNEL_GS_BASE;
	//msrs[n++].index = MSR_IA32_FEATURE_CONTROL;
	msr_data.info.nmsrs = n;

	kvm_ioctl(vcpufd, KVM_GET_SREGS, &sregs);
	kvm_ioctl(vcpufd, KVM_GET_REGS, &regs);
	kvm_ioctl(vcpufd, KVM_GET_MSRS, &msr_data);
	kvm_ioctl(vcpufd, KVM_GET_XCRS, &xcrs);
	kvm_ioctl(vcpufd, KVM_GET_LAPIC, &lapic);
	kvm_ioctl(vcpufd, KVM_GET_FPU, &fpu);
	kvm_ioctl(vcpufd, KVM_GET_XSAVE, &xsave);
	kvm_ioctl(vcpufd, KVM_GET_VCPU_EVENTS, &events);
	kvm_ioctl(vcpufd, KVM_GET_MP_STATE, &mp_state);

	snprintf(fname, MAX_FNAME, "checkpoint/chk%u_core%u.dat", no_checkpoint, cpuid);

	FILE* f = fopen(fname, "w");
	if (f == NULL) {
		err(1, "fopen: unable to open file\n");
	}

	if (fwrite(&sregs, sizeof(sregs), 1, f) != 1)
		err(1, "fwrite failed\n");
	if (fwrite(&regs, sizeof(regs), 1, f) != 1)
		err(1, "fwrite failed\n");
	if (fwrite(&fpu, sizeof(fpu), 1, f) != 1)
		err(1, "fwrite failed\n");
	if (fwrite(&msr_data, sizeof(msr_data), 1, f) != 1)
		err(1, "fwrite failed\n");
	if (fwrite(&lapic, sizeof(lapic), 1, f) != 1)
		err(1, "fwrite failed\n");
	if (fwrite(&xsave, sizeof(xsave), 1, f) != 1)
		err(1, "fwrite failed\n");
	if (fwrite(&xcrs, sizeof(xcrs), 1, f) != 1)
		err(1, "fwrite failed\n");
	if (fwrite(&events, sizeof(events), 1, f) != 1)
		err(1, "fwrite failed\n");
	if (fwrite(&mp_state, sizeof(mp_state), 1, f) != 1)
		err(1, "fwrite failed\n");

	fclose(f);
}

static void sigusr_handler(int signum)
{
	pthread_barrier_wait(&barrier);

	save_cpu_state();

	pthread_barrier_wait(&barrier);
}

static void* uhyve_thread(void* arg)
{
	size_t ret;
	struct sigaction sa;

	pthread_cleanup_push(uhyve_exit, NULL);

	cpuid = (size_t) arg;

	/* Install timer_handler as the signal handler for SIGVTALRM. */
	memset(&sa, 0x00, sizeof(sa));
	sa.sa_handler = &sigusr_handler;
	sigaction(SIGRTMIN, &sa, NULL);

	// create new cpu
	vcpu_init();

	// run cpu loop until thread gets killed
	ret = vcpu_loop();

	pthread_cleanup_pop(1);

	return (void*) ret;
}

void sigterm_handler(int signum)
{
	pthread_exit(0);
}

int uhyve_init(char** argv)
{
	const char* path = argv[1];
	const char *hermit_seccomp = getenv("HERMIT_SECCOMP");
	signal(SIGTERM, sigterm_handler);

	if(hermit_seccomp && atoi(hermit_seccomp) != 0)
		uhyve_seccomp_enabled = true;

	// register routine to close the VM
	atexit(uhyve_atexit);

	FILE* f = fopen("checkpoint/chk_config.txt", "r");
	if (f != NULL) {
		int tmp = 0;
		restart = true;

		fscanf(f, "number of cores: %u\n", &ncores);
		fscanf(f, "memory size: 0x%zx\n", &guest_size);
		fscanf(f, "checkpoint number: %u\n", &no_checkpoint);
		fscanf(f, "entry point: 0x%zx\n", &elf_entry);
		fscanf(f, "full checkpoint: %d", &tmp);
		full_checkpoint = tmp ? true : false;

		if (verbose)
			fprintf(stderr, "Restart from checkpoint %u (ncores %d, mem size 0x%zx)\n", no_checkpoint, ncores, guest_size);
		fclose(f);
	} else {
		const char* hermit_memory = getenv("HERMIT_MEM");
		if (hermit_memory)
			guest_size = memparse(hermit_memory);

		const char* hermit_cpus = getenv("HERMIT_CPUS");
		if (hermit_cpus)
			ncores = (uint32_t) atoi(hermit_cpus);

		const char* full_chk = getenv("HERMIT_FULLCHECKPOINT");
		if (full_chk && (strcmp(full_chk, "0") != 0)) {
			printf("full\n");
			full_checkpoint = true;
		}
	}

	vcpu_threads = (pthread_t*) calloc(ncores, sizeof(pthread_t));
	if (!vcpu_threads)
		err(1, "Not enough memory");

	vcpu_fds = (int*) calloc(ncores, sizeof(int));
	if (!vcpu_fds)
		err(1, "Not enough memory");

	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm < 0)
		err(1, "Could not open: /dev/kvm");

	/* Make sure we have the stable version of the API */
	int kvm_api_version = kvm_ioctl(kvm, KVM_GET_API_VERSION, NULL);
	if (kvm_api_version != 12)
		err(1, "KVM: API version is %d, uhyve requires version 12", kvm_api_version);

	/* Create the virtual machine */
	vmfd = kvm_ioctl(kvm, KVM_CREATE_VM, 0);

	/* Initialize seccomp filter */
	if(uhyve_seccomp_enabled) {
		if(uhyve_seccomp_init(vmfd)) {
			fprintf(stderr, "Error configuring seccomp\n");
			exit(-1);
		}
	}

	uint64_t identity_base = 0xfffbc000;
	if (ioctl(vmfd, KVM_CHECK_EXTENSION, KVM_CAP_SYNC_MMU) > 0) {
		/* Allows up to 16M BIOSes. */
		identity_base = 0xfeffc000;

		kvm_ioctl(vmfd, KVM_SET_IDENTITY_MAP_ADDR, &identity_base);
	}
	kvm_ioctl(vmfd, KVM_SET_TSS_ADDR, identity_base + 0x1000);

	/*
	 * Allocate page-aligned guest memory.
	 *
	 * TODO: support of huge pages
	 */
	if (guest_size < KVM_32BIT_GAP_START) {
		guest_mem = mmap(NULL, guest_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (guest_mem == MAP_FAILED)
			err(1, "mmap failed");
	} else {
		guest_size += KVM_32BIT_GAP_SIZE;
		guest_mem = mmap(NULL, guest_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (guest_mem == MAP_FAILED)
			err(1, "mmap failed");

		/*
		 * We mprotect the gap PROT_NONE so that if we accidently write to it, we will know.
		 */
		mprotect(guest_mem + KVM_32BIT_GAP_START, KVM_32BIT_GAP_SIZE, PROT_NONE);
	}

	const char* merge = getenv("HERMIT_MERGEABLE");
	if (merge && (strcmp(merge, "0") != 0)) {
		/*
		 * The KSM feature is intended for applications that generate
		 * many instances of the same data (e.g., virtualization systems
		 * such as KVM). It can consume a lot of processing power!
		 */
		madvise(guest_mem, guest_size, MADV_MERGEABLE);
		if (verbose)
			fprintf(stderr, "VM uses KSN feature \"mergeable\" to reduce the memory footprint.\n");
	}

	struct kvm_userspace_memory_region kvm_region = {
		.slot = 0,
		.guest_phys_addr = GUEST_OFFSET,
		.memory_size = guest_size,
		.userspace_addr = (uint64_t) guest_mem,
#ifdef USE_DIRTY_LOG
		.flags = KVM_MEM_LOG_DIRTY_PAGES,
#else
		.flags = 0,
#endif
	};

	if (guest_size <= KVM_32BIT_GAP_START - GUEST_OFFSET) {
		kvm_ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &kvm_region);
	} else {
		kvm_region.memory_size = KVM_32BIT_GAP_START - GUEST_OFFSET;
		kvm_ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &kvm_region);

		kvm_region.slot = 1;
		kvm_region.guest_phys_addr = KVM_32BIT_GAP_START+KVM_32BIT_GAP_SIZE;
		kvm_region.memory_size = guest_size - KVM_32BIT_GAP_SIZE - KVM_32BIT_GAP_START + GUEST_OFFSET;
		kvm_ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &kvm_region);
	}

	kvm_ioctl(vmfd, KVM_CREATE_IRQCHIP, NULL);

#ifdef KVM_CAP_X2APIC_API
	// enable x2APIC support
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_X2APIC_API,
		.flags = 0,
		.args[0] = KVM_X2APIC_API_USE_32BIT_IDS|KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK,
	};
	kvm_ioctl(vmfd, KVM_ENABLE_CAP, &cap);
#endif

	// initialited IOAPIC with HermitCore's default settings
	struct kvm_irqchip chip;
	chip.chip_id = KVM_IRQCHIP_IOAPIC;
	kvm_ioctl(vmfd, KVM_GET_IRQCHIP, &chip);
	for(int i=0; i<KVM_IOAPIC_NUM_PINS; i++) {
		chip.chip.ioapic.redirtbl[i].fields.vector = 0x20+i;
		chip.chip.ioapic.redirtbl[i].fields.delivery_mode = 0;
		chip.chip.ioapic.redirtbl[i].fields.dest_mode = 0;
		chip.chip.ioapic.redirtbl[i].fields.delivery_status = 0;
		chip.chip.ioapic.redirtbl[i].fields.polarity = 0;
		chip.chip.ioapic.redirtbl[i].fields.remote_irr = 0;
		chip.chip.ioapic.redirtbl[i].fields.trig_mode = 0;
		chip.chip.ioapic.redirtbl[i].fields.mask = i != 2 ? 0 : 1;
		chip.chip.ioapic.redirtbl[i].fields.dest_id = 0;
	}
	kvm_ioctl(vmfd, KVM_SET_IRQCHIP, &chip);

	// try to detect KVM extensions
	cap_tsc_deadline = kvm_ioctl(vmfd, KVM_CHECK_EXTENSION, KVM_CAP_TSC_DEADLINE_TIMER) <= 0 ? false : true;
	cap_irqchip = kvm_ioctl(vmfd, KVM_CHECK_EXTENSION, KVM_CAP_IRQCHIP) <= 0 ? false : true;
#ifdef KVM_CLOCK_TSC_STABLE
	cap_adjust_clock_stable = kvm_ioctl(vmfd, KVM_CHECK_EXTENSION, KVM_CAP_ADJUST_CLOCK) == KVM_CLOCK_TSC_STABLE ? true : false;
#endif
	cap_irqfd = kvm_ioctl(vmfd, KVM_CHECK_EXTENSION, KVM_CAP_IRQFD) <= 0 ? false : true;
	if (!cap_irqfd)
		err(1, "the support of KVM_CAP_IRQFD is curently required");
	// TODO: add VAPIC support
	cap_vapic = kvm_ioctl(vmfd, KVM_CHECK_EXTENSION, KVM_CAP_VAPIC) <= 0 ? false : true;
	//if (cap_vapic)
	//	printf("System supports vapic\n");

    // create PIT
    struct kvm_pit_config pit_config = { .flags = 0, };
    int retpierre = kvm_ioctl(vmfd, KVM_CREATE_PIT2, &pit_config);

	const char* hermit_tux;
	hermit_tux = getenv("HERMIT_TUX");
	if (hermit_tux)
	{
		if (argv[2] == NULL) {
			fprintf(stderr, "Hermitux: linux binary missing\n");
			exit(EXIT_FAILURE);
		}
		strcpy(htux_bin, argv[2]);
		strcpy(htux_kernel, argv[1]);
	}


	if (restart) {
		if (load_checkpoint(guest_mem, path) != 0)
			exit(EXIT_FAILURE);
	} else {
		if (load_kernel(guest_mem, path) != 0)
			exit(EXIT_FAILURE);
		if (hermit_tux)
			if (uhyve_elf_loader(htux_bin) < 0)
				exit(EXIT_FAILURE);
	}

	pthread_barrier_init(&barrier, NULL, ncores);
	cpuid = 0;

	// create first CPU, it will be the boot processor by default
	int ret = vcpu_init();

	const char* netif_str = getenv("HERMIT_NETIF");
	if (netif_str && strcmp(netif_str, ""))
	{
		// TODO: strncmp for different network interfaces
		// for example tun/tap device or uhyvetap device
		netfd = uhyve_net_init(netif_str);
		if (netfd < 0)
			err(1, "unable to initialized network");
	}

	return ret;
}

static void timer_handler(int signum)
{
	struct stat st = {0};
	const size_t flag = (!full_checkpoint && (no_checkpoint > 0)) ? PG_DIRTY : PG_ACCESSED;
	char fname[MAX_FNAME];
	struct timeval begin, end;

	if (verbose)
		gettimeofday(&begin, NULL);

	if (stat("checkpoint", &st) == -1)
		mkdir("checkpoint", 0700);

	for(size_t i = 0; i < ncores; i++)
		if (vcpu_threads[i] != pthread_self())
			pthread_kill(vcpu_threads[i], SIGRTMIN);

	pthread_barrier_wait(&barrier);

	save_cpu_state();

	snprintf(fname, MAX_FNAME, "checkpoint/chk%u_mem.dat", no_checkpoint);

	FILE* f = fopen(fname, "w");
	if (f == NULL) {
		err(1, "fopen: unable to open file");
	}

	/*struct kvm_irqchip irqchip = {};
	if (cap_irqchip)
		kvm_ioctl(vmfd, KVM_GET_IRQCHIP, &irqchip);
	else
		memset(&irqchip, 0x00, sizeof(irqchip));
	if (fwrite(&irqchip, sizeof(irqchip), 1, f) != 1)
		err(1, "fwrite failed");*/

	struct kvm_clock_data clock = {};
	kvm_ioctl(vmfd, KVM_GET_CLOCK, &clock);
	if (fwrite(&clock, sizeof(clock), 1, f) != 1)
		err(1, "fwrite failed");

#if 0
	if (fwrite(guest_mem, guest_size, 1, f) != 1)
		err(1, "fwrite failed");
#elif defined(USE_DIRTY_LOG)
	static struct kvm_dirty_log dlog = {
		.slot = 0,
		.dirty_bitmap = NULL
	};
	size_t dirty_log_size = (guest_size >> PAGE_BITS) / sizeof(size_t);

	// do we create our first checkpoint
	if (dlog.dirty_bitmap == NULL)
	{
		// besure that all paddings are zero
		memset(&dlog, 0x00, sizeof(dlog));

		dlog.dirty_bitmap = malloc(dirty_log_size * sizeof(size_t));
		if (dlog.dirty_bitmap == NULL)
			err(1, "malloc failed!\n");
	}
	memset(dlog.dirty_bitmap, 0x00, dirty_log_size * sizeof(size_t));

	dlog.slot = 0;
nextslot:
	kvm_ioctl(vmfd, KVM_GET_DIRTY_LOG, &dlog);

	for(size_t i=0; i<dirty_log_size; i++)
	{
		size_t value = ((size_t*) dlog.dirty_bitmap)[i];

		if (value)
		{
			for(size_t j=0; j<sizeof(size_t)*8; j++)
			{
				size_t test = 1ULL << j;

				if ((value & test) == test)
				{
					size_t addr = (i*sizeof(size_t)*8+j)*PAGE_SIZE;

					if (fwrite(&addr, sizeof(size_t), 1, f) != 1)
						err(1, "fwrite failed");
					if (fwrite((size_t*) (guest_mem + addr), PAGE_SIZE, 1, f) != 1)
						err(1, "fwrite failed");
				}
			}
		}
	}

	// do we have to check the second slot?
	if ((dlog.slot == 0) && (guest_size > KVM_32BIT_GAP_START - GUEST_OFFSET)) {
		dlog.slot = 1;
		memset(dlog.dirty_bitmap, 0x00, dirty_log_size * sizeof(size_t));
		goto nextslot;
	}
#else
	size_t* pml4 = (size_t*) (guest_mem+elf_entry+PAGE_SIZE);
	for(size_t i=0; i<(1 << PAGE_MAP_BITS); i++) {
		if ((pml4[i] & PG_PRESENT) != PG_PRESENT)
			continue;
		//printf("pml[%zd] 0x%zx\n", i, pml4[i]);
		size_t* pdpt = (size_t*) (guest_mem+(pml4[i] & PAGE_MASK));
		for(size_t j=0; j<(1 << PAGE_MAP_BITS); j++) {
			if ((pdpt[j] & PG_PRESENT) != PG_PRESENT)
				continue;
			//printf("\tpdpt[%zd] 0x%zx\n", j, pdpt[j]);
			size_t* pgd = (size_t*) (guest_mem+(pdpt[j] & PAGE_MASK));
			for(size_t k=0; k<(1 << PAGE_MAP_BITS); k++) {
				if ((pgd[k] & PG_PRESENT) != PG_PRESENT)
					continue;
				//printf("\t\tpgd[%zd] 0x%zx\n", k, pgd[k] & ~PG_XD);
				if ((pgd[k] & PG_PSE) != PG_PSE) {
					size_t* pgt = (size_t*) (guest_mem+(pgd[k] & PAGE_MASK));
					for(size_t l=0; l<(1 << PAGE_MAP_BITS); l++) {
						if ((pgt[l] & (PG_PRESENT|flag)) == (PG_PRESENT|flag)) {
							//printf("\t\t\t*pgt[%zd] 0x%zx, 4KB\n", l, pgt[l] & ~PG_XD);
							if (!full_checkpoint)
								pgt[l] = pgt[l] & ~(PG_DIRTY|PG_ACCESSED);
							size_t pgt_entry = pgt[l] & ~PG_PSE; // because PAT use the same bit as PSE
							if (fwrite(&pgt_entry, sizeof(size_t), 1, f) != 1)
								err(1, "fwrite failed");
							if (fwrite((size_t*) (guest_mem + (pgt[l] & PAGE_MASK)), (1UL << PAGE_BITS), 1, f) != 1)
								err(1, "fwrite failed");
						}
					}
				} else if ((pgd[k] & flag) == flag) {
					//printf("\t\t*pgd[%zd] 0x%zx, 2MB\n", k, pgd[k] & ~PG_XD);
					if (!full_checkpoint)
						pgd[k] = pgd[k] & ~(PG_DIRTY|PG_ACCESSED);
					if (fwrite(pgd+k, sizeof(size_t), 1, f) != 1)
						err(1, "fwrite failed");
					if (fwrite((size_t*) (guest_mem + (pgd[k] & PAGE_2M_MASK)), (1UL << PAGE_2M_BITS), 1, f) != 1)
						err(1, "fwrite failed");
				}
			}
		}
	}
#endif

	fclose(f);

	pthread_barrier_wait(&barrier);

	// update configuration file
	f = fopen("checkpoint/chk_config.txt", "w");
	if (f == NULL) {
		err(1, "fopen: unable to open file");
	}

	fprintf(f, "number of cores: %u\n", ncores);
	fprintf(f, "memory size: 0x%zx\n", guest_size);
	fprintf(f, "checkpoint number: %u\n", no_checkpoint);
	fprintf(f, "entry point: 0x%zx\n", elf_entry);
	if (full_checkpoint)
		fprintf(f, "full checkpoint: 1");
	else
		fprintf(f, "full checkpoint: 0");

	fclose(f);

	if (verbose) {
		gettimeofday(&end, NULL);
		size_t msec = (end.tv_sec - begin.tv_sec) * 1000;
		msec += (end.tv_usec - begin.tv_usec) / 1000;
		fprintf(stderr, "Create checkpoint %u in %zd ms\n", no_checkpoint, msec);
	}

	no_checkpoint++;
}

int uhyve_loop(int argc, char **argv)
{
	const char* hermit_check = getenv("HERMIT_CHECKPOINT");
	const char *hermit_debug = getenv("HERMIT_DEBUG");
	const char *hermit_profile = getenv("HERMIT_PROFILE");
	int ts = 0, i = 0;

	if(hermit_debug && atoi(hermit_debug) != 0)
		uhyve_gdb_enabled = true;

	if(hermit_profile && atoi(hermit_profile) != 0) {
		uhyve_profiler_enabled = true;
		uhyve_profiler_init(atoi(hermit_profile));
	}

	/* argv[0] is 'proxy', do not count it */
	uhyve_argc = argc-1;
	uhyve_argv = &argv[1];
	uhyve_envp = environ;
	while(uhyve_envp[i] != NULL)
		i++;
	uhyve_envc = i;

	if (uhyve_argc > MAX_ARGC_ENVC) {
		fprintf(stderr, "uhyve downsiize envc from %d to %d\n", uhyve_argc, MAX_ARGC_ENVC);
		uhyve_argc = MAX_ARGC_ENVC;
	}

	if (uhyve_envc > MAX_ARGC_ENVC-1) {
		fprintf(stderr, "uhyve downsiize envc from %d to %d\n", uhyve_envc, MAX_ARGC_ENVC-1);
		uhyve_envc = MAX_ARGC_ENVC-1;
	}

	if(uhyve_argc > MAX_ARGC_ENVC || uhyve_envc > MAX_ARGC_ENVC) {
		fprintf(stderr, "uhyve cannot forward more than %d command line "
			"arguments or environment variables, please consider increasing "
				"the MAX_ARGC_ENVP cmake argument\n", MAX_ARGC_ENVC);
		return -1;
	}

	if (hermit_check)
		ts = atoi(hermit_check);

	*((uint32_t*) (mboot+0x24)) = ncores;
	*((uint64_t*) (mboot + 0xC0)) = tux_entry;
	*((uint64_t*) (mboot + 0xC8)) = tux_size;
	*((uint64_t*) (mboot + 0xE2)) = tux_start_address;
	*((uint64_t*) (mboot + 0xEA)) = tux_ehdr_phoff;
	*((uint64_t*) (mboot + 0xF2)) = tux_ehdr_phnum;
	*((uint64_t*) (mboot + 0xFA)) = tux_ehdr_phentsize;

	/* epoch offset in secs */
	struct timeval tv;
	gettimeofday(&tv, NULL);
	*((uint64_t*) (mboot + 0x102)) = (long)tv.tv_sec;

	if(uhyve_gdb_enabled)
		*((uint8_t*) (mboot + 0xD0)) = 0x1;

	// First CPU is special because it will boot the system. Other CPUs will
	// be booted linearily after the first one.
	vcpu_threads[0] = pthread_self();

	// start threads to create VCPUs
	for(size_t i = 1; i < ncores; i++)
		pthread_create(&vcpu_threads[i], NULL, uhyve_thread, (void*) i);

	if (ts > 0)
	{
		struct sigaction sa;
		struct itimerval timer;

		/* Install timer_handler as the signal handler for SIGVTALRM. */
		memset(&sa, 0x00, sizeof(sa));
		sa.sa_handler = &timer_handler;
		sigaction(SIGALRM, &sa, NULL);

		/* Configure the timer to expire after "ts" sec... */
		timer.it_value.tv_sec = ts;
		timer.it_value.tv_usec = 0;
		/* ... and every "ts" sec after that. */
		timer.it_interval.tv_sec = ts;
		timer.it_interval.tv_usec = 0;
		/* Start a virtual timer. It counts down whenever this process is executing. */
		setitimer(ITIMER_REAL, &timer, NULL);
	}

	/* init uhyve gdb support */
	if(uhyve_gdb_enabled)
		uhyve_gdb_init(vcpufd);

	/* Add vcpu_fds to the seccomp filter then load it */
	if(uhyve_seccomp_enabled) {
		for(i=0; i<ncores; i++)
			if(uhyve_seccomp_add_vcpu_fd(vcpu_fds[i])) {
				fprintf(stderr, "Cannot add vcpu_fd to seccomp filter\n");
				exit(-1);
			}

		if(uhyve_seccomp_load()) {
			fprintf(stderr, "Cannot load seccomp filter\n");
			exit(-1);
		}
	}

	// Run first CPU
	return vcpu_loop();
}

