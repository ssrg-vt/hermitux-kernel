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

#include <elf.h>

#include "proxy.h"
#include "uhyve.h"
#include "uhyve-elf.h"

// Linux applications are always located at address 0x400000
#define linux_start_address	0x400000

size_t tux_entry = 0;
size_t tux_size = 0;

int uhyve_elf_loader(const char* path)
{
	Elf64_Ehdr hdr;
	Elf64_Phdr *phdr = NULL;
	size_t buflen;
	int fd, ret;

	if (verbose)
		fprintf(stderr, "Hello from uhyve's elf loader\n");

	fd = open(path, O_RDONLY);
	if (fd == -1)
	{
		perror("Unable to open file");
		return -1;
	}

	ret = pread_in_full(fd, &hdr, sizeof(hdr), 0);
	if (ret < 0)
		goto out;

	//  check if the program is a HermitCore file
	if (hdr.e_ident[EI_MAG0] != ELFMAG0
		|| hdr.e_ident[EI_MAG1] != ELFMAG1
		|| hdr.e_ident[EI_MAG2] != ELFMAG2
		|| hdr.e_ident[EI_MAG3] != ELFMAG3
		|| hdr.e_ident[EI_CLASS] != ELFCLASS64
		|| hdr.e_ident[EI_OSABI] != ELFOSABI_LINUX
		|| hdr.e_type != ET_EXEC || hdr.e_machine != EM_X86_64)
	{
		fprintf(stderr, "Inavlide elf file!\n");
		goto out;
	}

	if (verbose)
		fprintf(stderr, "uhyve found entry point at 0x%zx in file %s\n", hdr.e_entry, path);

	tux_entry = hdr.e_entry;
	buflen = hdr.e_phentsize * hdr.e_phnum;
	phdr = malloc(buflen);
	if (!phdr) {
		fprintf(stderr, "Not enough memory\n");
		goto out;
	}

	ret = pread_in_full(fd, phdr, buflen, hdr.e_phoff);
	if (ret < 0)
		goto out;

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

		if (verbose)
			printf("Load elf file at 0x%zx, file size 0x%zx, memory size 0x%zx\n", paddr, filesz, memsz);
		tux_size = paddr + memsz - linux_start_address;

		ret = pread_in_full(fd, guest_mem+paddr-GUEST_OFFSET, filesz, offset);
		if (ret < 0)
			goto out;

	}

out:
	if (phdr)
		free(phdr);

	close(fd);

	return 0;
}
