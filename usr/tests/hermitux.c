/*
 * Copyright (c) 2017-2019, Stefan Lankes, RWTH Aachen University
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

#define DIE()   __builtin_trap()

/* aarch64 has SP alignment constraints that force use to prepare the stack
 * on a separate buffer before pushing that buffer 16 bytes by 16 bytes. This
 * is the size of that buffer */
#define STACK_BUFFER_SIZE   4096

/* Needed to load the program headers */
#define O_RDONLY			0x0
#define SEEK_SET			0x0
typedef unsigned long long size_t;

/* Elf ABI */
#define AT_NULL				0
#define AT_IGNORE			1
#define AT_EXECFD			2
#define AT_PHDR				3
#define AT_PHENT			4
#define AT_PHNUM			5
#define AT_PAGESZ			6
#define AT_BASE				7
#define AT_FLAGS			8
#define AT_ENTRY			9
#define AT_NOTELF			10
#define AT_UID				11
#define AT_EUID				12
#define AT_GID				13
#define AT_EGID				14
#define AT_PLATFORM			15
#define AT_HWCAP			16
#define AT_CLKTCK			17
#define AT_DCACHEBSIZE		19
#define AT_ICACHEBSIZE		20
#define AT_UCACHEBSIZE		21
#define AT_SECURE			23
#define AT_RANDOM			25
#define AT_EXECFN			31
#define AT_SYSINFO_EHDR		33
#define AT_SYSINFO			32

#define EI_NIDENT	(16)

typedef unsigned long uint64_t;
typedef long int64_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned short uint16_t;
typedef short int16_t;
typedef unsigned char uint8_t;
typedef char int8_t;

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef	int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef	int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;
typedef Elf64_Half Elf64_Versym;

typedef struct {
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;

typedef struct {
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;

extern char **environ;

extern const size_t tux_entry;
extern const size_t tux_size;
extern const size_t tux_start_address;
extern const size_t tux_ehdr_phoff;
extern const size_t tux_ehdr_phnum;
extern const size_t tux_ehdr_phentsize;

/* Push two 8 bytes values on the stack, 'first' then 'second' */
static inline void push_couple(unsigned long long second, unsigned long long first) {
#ifdef __aarch64__
    asm volatile("stp %1, %0, [sp, #-16]!" :: "r"(first), "r"(second));
#else
	asm volatile("pushq %0" : : "r" (val));
	asm volatile("pushq %0" : : "r" (type));
#endif
}

static inline void push(unsigned long long val) {
#ifdef __aarch64__
	asm volatile("str %0, [sp, #-16]!" :: "r"(val));
#else
	asm volatile("pushq %0" : : "r" (val));
#endif
}

/* Space allocated for the program headers */
char phdr[4096];
Elf64_Ehdr hdr;

/* Space allocated for the buffer we use to prepare the stack */
uint64_t stack_buffer[STACK_BUFFER_SIZE/8];

#ifdef __aarch64__
char *auxv_platform = "aarch64";
#else
char *auxv_platform = "x86-64";
#endif

int main(int argc, char** argv) {
	unsigned long long int libc_argc = argc -1;
	int i, envc;

	/* count the number of environment variables */
	envc = 0;
	for (char **env = environ; *env; ++env) envc++;

	/* We need to push the element on the stack in the inverse order they will
	 * be read by the C library (i.e. argc in the end) */

	/* auxv */
	push_couple(AT_NULL, 0x0);
	push_couple(AT_IGNORE, 0x0);
	push_couple(AT_EXECFD, 0x0);
	push_couple(AT_PHDR, tux_start_address + tux_ehdr_phoff);
	push_couple(AT_PHNUM, tux_ehdr_phnum);
	push_couple(AT_PHENT, tux_ehdr_phentsize);
	push_couple(AT_RANDOM, tux_start_address); // FIXME get read random bytes
	push_couple(AT_BASE, 0x0);
	push_couple(AT_SYSINFO_EHDR, 0x0);
	push_couple(AT_SYSINFO, 0x0);
	push_couple(AT_PAGESZ, 4096);
	push_couple(AT_HWCAP, 0x0);
	push_couple(AT_CLKTCK, 0x64); // mimic Linux
	push_couple(AT_FLAGS, 0x0);
	push_couple(AT_ENTRY, tux_entry);
	push_couple(AT_UID, 0x0);
	push_couple(AT_EUID, 0x0);
	push_couple(AT_GID, 0x0);
	push_couple(AT_EGID, 0x0);
	push_couple(AT_SECURE, 0x0);
	push_couple(AT_SYSINFO, 0x0);
	push_couple(AT_EXECFN, (unsigned long long)argv[1]);
	push_couple(AT_DCACHEBSIZE, 0x0);
	push_couple(AT_ICACHEBSIZE, 0x0);
	push_couple(AT_UCACHEBSIZE, 0x0);
	push_couple(AT_NOTELF, 0x0);
	push_couple(AT_PLATFORM, (uint64_t)auxv_platform);

    /* aarch64's SP must always be 16 bytes so we can only push 8 bytes
     * elements 2 by 2. Also the SP when jumpign to the entry point must point
     * right on argc, followed by argv and so on. So, prepare a buffer that we
     * will push 16 bytes by 16 bytes to the stack, and use 8 bytes of padding
     * if needed in the form of a fake environment variable. THis buffer has
     * a size of a page. */
    int offset = 0;

	/*envp */
	/* Note that this will push NULL to the stack first, which is expected */
	for(i=(envc); i>=0; i--) {
        stack_buffer[offset++] = (uint64_t)environ[i];
    }

    /* We use a fake environment variable to add padding on the stack if
     * needed, in the case we need to align the final SP */
    if(((envc + libc_argc + 1) % 2) != 0)
        stack_buffer[offset++] = (uint64_t)"DUMMY_ENV_VAR=DUMMY_VAL";

	/* argv */
	/* Same as envp, pushing NULL first */
	for(i=libc_argc+1;i>0; i--) {
		stack_buffer[offset++] = (uint64_t)argv[i];
    }

	/* argc */
	stack_buffer[offset++] = libc_argc;

    /* Now push everything to the stack. keep in mind we made sure that
     * stack_buffer has an even number of members so it won't overflow here */
    if(offset % 2)
        DIE();
    for(i = 0; i < offset; i += 2)
        push_couple(stack_buffer[i+1], stack_buffer[i]);

#ifdef __aarch64__
    /* We clear x0, same issue as with x86-64 for rdx, see below */
	asm volatile("mov x0, #0");
	asm volatile("blr %0" : : "r" (tux_entry));
#else
	/* with GlibC, the dynamic linker sets in rdx the address of some code
	 * to be executed at exit (if != 0), however we are not using it and here
	 * it contains some garbage value, so clear it
	 */
	asm volatile("xor %rdx, %rdx");
	/* finally, jump to entry point */
	asm volatile("jmp *%0" : : "r" (tux_entry));
#endif

	return 0;
}
