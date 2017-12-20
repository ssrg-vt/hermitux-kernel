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

/* #include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>  */

/* Linux applications are always located at address 0x400000 */
#define tux_start_address	0x400000

/* Elf auxiliary vector defines */
#define AT_NULL				0
#define AT_RANDOM			25
#define AT_SYSINFO			32
#define AT_BASE				7

typedef unsigned long long size_t;

extern const size_t tux_entry;
extern const size_t tux_size;

extern char **environ;

void inline push_auxv(unsigned long long type, unsigned long long val) {
	asm volatile("pushq %0" : : "r" (val));
	asm volatile("pushq %0" : : "r" (type));
}

int main(int argc, char** argv)
{
	unsigned long long int libc_argc = argc -1;
	int i, envc;

	/* count the number of environment variables */
	envc = 0;
	for (char **env = environ; *env; ++env) envc++;

	/* We need to push the element on the stack in the inverse order they will 
	 * be read by the C library (i.e. argc in the end) */

	/* auxv */
	push_auxv(AT_NULL, 0x0);
	push_auxv(AT_RANDOM, 0x400000);
	push_auxv(AT_BASE, 0x0);
	push_auxv(AT_SYSINFO, 0x0);

	/*envp */
	/* Note that this will push NULL to the stack first, which is expected */
	asm volatile("pushq %0" : : "i" (0x0));
	for(i=(envc-1); i>=0; i--)
		asm volatile("pushq %0" : : "r" (environ[i]));

	/* argv */
	/* Same as envp, pushing NULL first */
	for(i=libc_argc+1;i>0; i--)
		asm volatile("pushq %0" : : "r" (argv[i]));

	/* argc */
	asm volatile("pushq %0" : : "r" (libc_argc));

	/* with GlibC, the dynamic linker sets in rdx the address of some code
	 * to be executed at exit (if != 0), however we are not using it and here
	 * it contains some garbage value, so clear it
	 */
	asm volatile("xor %rdx, %rdx");
	/* finally, jump to entry point */
	asm volatile("jmp *%0" : : "r" (tux_entry));

	return 0;
}
