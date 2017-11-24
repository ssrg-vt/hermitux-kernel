#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define EI_NIDENT (16)

#define EI_MAG0		0		/* File identification byte 0 index */
#define ELFMAG0		0x7f		/* Magic number byte 0 */
#define EI_MAG1		1		/* File identification byte 1 index */
#define ELFMAG1		'E'		/* Magic number byte 1 */
#define EI_MAG2		2		/* File identification byte 2 index */
#define ELFMAG2		'L'		/* Magic number byte 2 */
#define EI_MAG3		3		/* File identification byte 3 index */
#define ELFMAG3		'F'		/* Magic number byte 3 */

#define EI_CLASS	4		/* File class byte index */
#define ELFCLASSNONE	0		/* Invalid class */
#define ELFCLASS32	1		/* 32-bit objects */
#define ELFCLASS64	2		/* 64-bit objects */
#define ELFCLASSNUM	3

#define EI_OSABI	7		/* OS ABI identification */
#define ELFOSABI_NONE		0	/* UNIX System V ABI */
#define ELFOSABI_SYSV		0	/* Alias.  */
#define ELFOSABI_HPUX		1	/* HP-UX */
#define ELFOSABI_NETBSD		2	/* NetBSD.  */
#define ELFOSABI_GNU		3	/* Object uses GNU ELF extensions.  */
#define ELFOSABI_LINUX		ELFOSABI_GNU /* Compatibility alias.  */
#define ELFOSABI_SOLARIS	6	/* Sun Solaris.  */
#define ELFOSABI_AIX		7	/* IBM AIX.  */
#define ELFOSABI_IRIX		8	/* SGI Irix.  */
#define ELFOSABI_FREEBSD	9	/* FreeBSD.  */
#define ELFOSABI_TRU64		10	/* Compaq TRU64 UNIX.  */
#define ELFOSABI_MODESTO	11	/* Novell Modesto.  */
#define ELFOSABI_OPENBSD	12	/* OpenBSD.  */
#define ELFOSABI_ARM_AEABI	64	/* ARM EABI */
#define ELFOSABI_ARM		97	/* ARM */
#define ELFOSABI_STANDALONE	255	/* Standalone (embedded) application */

#define ET_NONE		0		/* No file type */
#define ET_REL		1		/* Relocatable file */
#define ET_EXEC		2		/* Executable file */
#define ET_DYN		3		/* Shared object file */
#define ET_CORE		4		/* Core file */
#define	ET_NUM		5		/* Number of defined types */
#define ET_LOOS		0xfe00		/* OS-specific range start */
#define ET_HIOS		0xfeff		/* OS-specific range end */
#define ET_LOPROC	0xff00		/* Processor-specific range start */
#define ET_HIPROC	0xffff		/* Processor-specific range end */

/* machine */
#define EM_X86_64	62	/* AMD x86-64 architecture */

typedef uint64_t Elf64_Addr;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Off;
typedef uint64_t Elf64_Xword;

typedef struct
{
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

typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;

/* Linux applications are always located at address 0x400000 */
#define tux_start_address	0x400000

extern const size_t tux_entry;
extern const size_t tux_size;

extern char **environ;

int load_linux_binary(char *path) {
	int fd, ret;
	Elf64_Ehdr hdr;

	/* First read the file */
	fd = open(path, O_RDONLY);
	if(fd == -1) {
		fprintf(stderr, "Unable to find a Linux image!!!\n");
		return -1;
	}

	ret = read(fd, &hdr, sizeof(hdr));
	if(ret != sizeof(hdr)) {
		fprintf(stderr, "Cannot read ELF header\n");
		return -1;
	}

	/*  check if the program is a HermitCore file */
	if (hdr.e_ident[EI_MAG0] != ELFMAG0
		|| hdr.e_ident[EI_MAG1] != ELFMAG1
		|| hdr.e_ident[EI_MAG2] != ELFMAG2
		|| hdr.e_ident[EI_MAG3] != ELFMAG3
		|| hdr.e_ident[EI_CLASS] != ELFCLASS64
		|| (hdr.e_ident[EI_OSABI] != ELFOSABI_LINUX &&
		hdr.e_ident[EI_OSABI] != ELFOSABI_NONE)
		|| hdr.e_type != ET_EXEC || hdr.e_machine != EM_X86_64)	{
		fprintf(stderr, "Inavlide elf file!\n");
		return -1;
	}
	
	fprintf(stderr, "Found entry point at 0x%zx in file %s\n", hdr.e_entry, path);

	
	
	close(fd);
	return 0;
}

int main(int argc, char** argv)
{
	unsigned long long int libc_argc = argc -1;
	int i, envc;
	
	printf("Hello from HermiTux QEMU loader\n\n");
	
	if(argc < 2) {
		fprintf(stderr, "Error, please indicate a linux binary after " 
				"hermitux-qemu on the command line");
		return -1;
	}

	if(load_linux_binary(argv[1]))
		return -1;

	if (tux_entry >= tux_start_address) {
		printf("Found linux image at 0x%zx with a size of 0x%zx\n", 
				tux_start_address, tux_size);
		printf("Entry point is located at 0x%zx\n", tux_entry);

		printf("Value of first byte at entry point: 0x%zx\n", 
				(size_t) *((char*) tux_entry));
	} else 
		fprintf(stderr, "Unable to find a Linux image!!!\n");


	/* count the number of environment variables */
	envc = 0;
	for (char **env = environ; *env; ++env) envc++;

	/* Befre jumping to the entry point we need to construct the stack with 
	 * argc, argv, envp, and auxv according to the linux convention. The layout
	 * shoud be:
	 * rsp --> [ argc ]       integer, 8 bytes
	 *         [ argv[0] ]    pointer, 8 bytes
	 *         [ argv[1] ]    pointer, 8 bytes
	 *         ...
	 *         [ argv[argc] ] (NULL) pointer, 8 bytes
	 *
	 *         [ envp[0] ]    pointer, 8 bytes
	 *         [ envp[1] ]    pointer, 8 bytes
	 *         ...
	 *         [ envp[N] ]    (NULL) pointer, 8 bytes
	 *
	 *         [ auxv[0] (Elf64_auxv_t] ] data structure, 16 bytes
	 *         [ auxv[1] *Elf64_auxv_t) ] data structure, 16 bytes
	 *         ...
	 *         TODO termination
	 *         Adapted from:
	 *         http://articles.manugarg.com/aboutelfauxiliaryvectors
	 */

	/* We need to push the element on the stack in the inverse order they will 
	 * be read by the C library (i.e. argc in the end) */

	/* auxv */
	/* TODO here, for now all the aux vectors data structures are filled
	 * with zeros */
	for(i=0; i<38*2; i++)
		asm volatile("pushq %0" : : "i" (0x00));

	/*envp */
	/* Note that this will push NULL to the stack first, which is expected */
	for(i=(envc); i>=0; i--)
		asm volatile("pushq %0" : : "r" (environ[i]));

	/* argv */
	/* Same as envp, pushing NULL first */
	for(i=libc_argc+1;i>0; i--)
		asm volatile("pushq %0" : : "r" (argv[i]));

	/* argc */
	asm volatile("pushq %0" : : "r" (libc_argc));

	printf("Jumping to 0x%x\n", tux_entry);
	asm volatile("jmp *%0" : : "r" (tux_entry));

	return 0;
}
