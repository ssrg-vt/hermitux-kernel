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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#define N	255

char *hello = "Hello World from the assembler!!\n";
int l;

static void test_handler(int s)
{
	printf("Receive signal with number %d\n", s);
}

int main(int argc, char** argv)
{
	int i, random;
	FILE* file;

	int fd = 1;
	int scno = 14;
	
	// For ASM code
	l = strlen(hello);

	// register test handler
	signal(SIGUSR1, test_handler);

	printf("Hello World!!!\n");
	//for(i=0; environ[i]; i++)
	//	printf("environ[%d] = %s\n", i, environ[i]);
	for(i=0; i<argc; i++)
		printf("argv[%d] = %s\n", i, argv[i]);

	raise(SIGUSR1);

	/*
	unsigned long int size = 10000*4096;
	void *a = malloc(size);
	memset(a, 0, size);
	*/
	
	file = fopen("/etc/hostname", "r");
	if (file)
	{
		char fname[N] = "";

		fscanf(file, "%s", fname);
		printf("Hostname: %s\n", fname);
		fclose(file);
	} else fprintf(stderr, "Unable to open file /etc/hostname\n");

	file = fopen("/tmp/test.txt", "w");
	if (file)
	{
		fprintf(file, "Hello World!!!\n");
		fclose(file);
	} else fprintf(stderr, "Unable to open file /tmp/test.txt\n");


	printf("hello is at %p\n", &hello);
	//printf("l = %d\n", l);

	//printf("now divinding by 0 %d\n", 5/0);
		
	
	asm  ( 	"mov	$1, %%rax\n\t"
		"mov 	$1, %%rdi\n\t"
		"mov	hello, %%rsi\n\t"
		"mov 	l, %%rdx\n\t"
		//"int $0x06\n\t"
		"syscall\n\t"
		
		:
		:
		: "%rax", "%rdi", "%rsi", "%rdx"
		);


	/*
	asm  ( 	"mov	$1, %rax\n\t"
		"mov 	$1, %rdi\n\t"
		"mov	$message, %rsi\n\t"
		"mov 	$20, %rdx\n\t"
		"int $0x80\n\t"

		"message: .ascii \"Hello World (ASM)!\n\"\n\t"
		);

	
	int retval;
	asm volatile ("int $0x80"
		      : "=a" (retval)
		      : "a" (4), "b" (1), "c" (hello), "d" (sizeof(hello)-1)
		      : "memory");
	asm volatile ("syscall" : : "a" (1), "b" (0));
	*/

	printf("Returned from syscall\n");

	return 0;
}
