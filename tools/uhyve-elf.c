/*
* Copyright (c) 2017, Stefan Lankes, RWTH Aachen University
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

#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include <elf.h>

#include "proxy.h"
#include "uhyve.h"
#include "uhyve-elf.h"

#define PAGE_BITS			12
#define PAGE_MASK			((~0UL) << PAGE_BITS)
#define PAGE_FLOOR(addr) 	((addr) & PAGE_MASK)

size_t tux_entry = 0;
size_t tux_size = 0;
size_t tux_start_address = 0;
size_t tux_ehdr_phoff = 0;
size_t tux_ehdr_phnum = 0;
size_t tux_ehdr_phentsize = 0;

static uint64_t pie_offset = 0;

int uhyve_elf_loader(const char* path) {
	Elf64_Ehdr hdr;
	Elf64_Phdr *phdr = NULL;
	size_t buflen;
	int fd, ret;

	if (verbose)
		fprintf(stderr, "Uhyve's elf loader starts, considering: %s\n", path);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Unable to open application file %s", path);
		return -1;
	}

	ret = pread_in_full(fd, &hdr, sizeof(hdr), 0);
	if (ret < 0)
		goto out;

	//  check the validity of the binary
	if (hdr.e_ident[EI_MAG0] != ELFMAG0
		|| hdr.e_ident[EI_MAG1] != ELFMAG1
		|| hdr.e_ident[EI_MAG2] != ELFMAG2
		|| hdr.e_ident[EI_MAG3] != ELFMAG3
		|| hdr.e_ident[EI_CLASS] != ELFCLASS64
		|| (hdr.e_ident[EI_OSABI] != ELFOSABI_LINUX
			&& hdr.e_ident[EI_OSABI] != ELFOSABI_NONE)
		|| hdr.e_machine != EM_X86_64
		|| (hdr.e_type != ET_EXEC && hdr.e_type != ET_DYN)) {

		fprintf(stderr, "Inavlid elf file %d!\n", hdr.e_type);
		ret = -1;
		goto out;
	}

	buflen = hdr.e_phentsize * hdr.e_phnum;
	phdr = malloc(buflen);
	if (!phdr) {
		fprintf(stderr, "Not enough memory\n");
		ret = -1;
		goto out;
	}

	/* We need to pass this to the guest so that it knows where the program
	 * headers are mapped: start address + this offset */
	tux_ehdr_phoff = hdr.e_phoff;
	tux_ehdr_phnum = hdr.e_phnum;
	tux_ehdr_phentsize = hdr.e_phentsize;

	ret = pread_in_full(fd, phdr, buflen, hdr.e_phoff);
	if (ret < 0)
		goto out;

	if(hdr.e_type == ET_DYN) {
		/* First check for the absence of PT_INTERP, otherwise we are looking
		 * at a purely dynamically compiled binary which we do not support
		 * (we only support static pie/non-pie ones. Getting a static pie
		 * binary involving some tricks with the linker that makes the binary
		 * type be ET_DYN but it is actually still a static binary. Look here:
		 * https://www.openwall.com/lists/musl/2015/06/01/12 */

		for (Elf64_Half ph_i = 0; ph_i < hdr.e_phnum; ph_i++) {
			if (phdr[ph_i].p_type == PT_INTERP) {
				fprintf(stderr, "ERROR: HermiTux only supports static "
						"binaries!\n");
				ret = -1;
				goto out;
			}
		}

		/* ASLR: The range we can load currently is from 0x400000 to
		 * 0x30000000. Segments need to be page aligne so the number of
		 * possibilities is (0x30000000 - 0x400000) / 0x1000 = 0x2FC00 (about
		 * 200000 possibilities) */

		srand(time(0));
		pie_offset = 0x400000 + PAGE_FLOOR(rand()%(0x30000000 - 0x400000));
		printf("PIE detected, loading application at 0x%llx\n", pie_offset);
	}

	tux_entry = hdr.e_entry + pie_offset;
	if(verbose)
		fprintf(stderr, "Uhyve's elf loader found entry point at 0x%zx in file "
				"%s\n", hdr.e_entry + pie_offset, path);

	/*
	 * Load all segments with type "LOAD" from the file at offset
	 * p_offset, and copy that into in memory.
	 */
	for (Elf64_Half ph_i = 0; ph_i < hdr.e_phnum; ph_i++) {
		uint64_t paddr = phdr[ph_i].p_paddr;
		size_t offset = phdr[ph_i].p_offset;
		size_t filesz = phdr[ph_i].p_filesz;
		size_t memsz = phdr[ph_i].p_memsz;

		if (phdr[ph_i].p_type != PT_LOAD)
			continue;

		if(!tux_start_address || (paddr + pie_offset < tux_start_address))
			tux_start_address = paddr + pie_offset;

		if (verbose)
			printf("Load elf file at 0x%zx, file size 0x%zx, memory size "
					"0x%zx\n", paddr + pie_offset, filesz, memsz);
		tux_size = paddr + memsz - tux_start_address + pie_offset;

		ret = pread_in_full(fd, guest_mem+paddr-GUEST_OFFSET + pie_offset,
				filesz, offset);

		if (ret < 0) {
			fprintf(stderr, "Cannot load segment\n");
			goto out;
		}
	}

out:
	if (phdr)
		free(phdr);

	close(fd);

	return ret;
}
