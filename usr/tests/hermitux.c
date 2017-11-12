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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Linux applications are always located at address 0x400000
#define tux_start_address	0x400000


#define GET_REG( var, reg, size ) asm volatile("mov"size" %%"reg", %0" : "=m" (var) )
#define GET_REG64( var, reg ) GET_REG( var, reg, "q")
#define GET_RSP( var ) GET_REG64( var, "rsp" )
#define SET_RIP_IMM( var ) asm volatile("movq %0, -0x8(%%rsp); jmpq *-0x8(%%rsp)" : : "m" (var) )

extern const size_t tux_entry;
extern const size_t tux_size;

extern char **environ;

int main(int argc, char** argv)
{
	unsigned long long int libc_argc = argc -1;
	int i, envc;

	printf("Hello from HermiTux loader\n\n");

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
	 *         TODO auxv: unclear for now
	 *
	 *         Adapted from:
	 *         http://articles.manugarg.com/aboutelfauxiliaryvectors
	 */

	/* We need to push the element on the stack in the inverse order they will 
	 * be read by the C library (i.e. argc in the end) */

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
