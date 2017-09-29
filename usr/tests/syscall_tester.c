#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <fcntl.h>

#define RUNS 25

/* For the write_asm function, the C variables used inside the asm()
   construct need to have global scope. */
volatile size_t fd_g = 0;
volatile char *buf_g;
volatile size_t len_g;
volatile ssize_t ret_g;
volatile size_t exit_arg_g;

static ssize_t write_asm(int fd, char *buf)
{
	/* Take arguments and assign them to globally declared variables
	   so we can use them in the asm() construct */
	fd_g = fd;
	buf_g = buf;
	len_g = strlen(buf);

	asm volatile("mfence":::"memory");
	asm volatile  (	"mov	$1, %%rax\n\t"
			"mov	fd_g, %%rdi\n\t"
			"mov	buf_g, %%rsi\n\t"
			"mov 	len_g, %%rdx\n\t"
			"syscall\n\t"
			"mov    %%rax, ret_g\n\t"
			:
			:
			: "%rax", "%rdi", "%rsi", "%rdx"
			);
	
	return ret_g;
}


static void exit_asm (int exit_arg)
{
	exit_arg_g = exit_arg;

	asm volatile ( "mov $60, %%rax\n\t"
		       "mov exit_arg_g, %%rdi\n\t"
		       "syscall\n\t"
		       :
		       :
		       : "%rax", "%rdi"
		     );
}


static ssize_t printf_asm(char *buf)
{
	return write_asm(1, buf);
}


static void write_tester(void)
{
	ssize_t ret;

	ret = printf_asm("Hello World from the assembler!!\n");
	printf("Returned from first syscall\n");
	printf("%zd values were printed\n\n", ret);

	ret = printf_asm("Hello once again from the assembler!!\n");
	printf("Returned from second syscall\n");
	printf("%zd values were printed\n\n", ret);
}


static void exit_tester(void)
{
	printf("Now exiting using a static syscall\n");
	exit_asm(0);
	printf("You should not be seeing this\n");
}


static void syscall_eval(void)
{
	int i, fd, l;
	struct timeval start, finish, diff;
	char *test1 = "Writing to file via normal method\n";
	char *test2 = "Writing to file via system call..\n";

	l = strlen(test1);
	fd = open("syscall_output.txt", O_CREAT | O_WRONLY);

	printf("Writing to file via normal method %d times\n", RUNS);
	gettimeofday(&start, NULL);
	for(i = 0; i < RUNS; i++) {
		sys_write(fd, test1, l);
	}
	gettimeofday(&finish, NULL);
	timersub(&finish, &start, &diff);
	printf("Time = %lld.%06lld seconds\n", diff.tv_sec, diff.tv_usec);

	printf("Writing to file via system call %d times\n", RUNS);
	gettimeofday(&start, NULL);
	for(i = 0; i < RUNS; i++) {
		write_asm(fd, test2);
	}

	printf("%s\n", test2);
	gettimeofday(&finish, NULL);
	timersub(&finish, &start, &diff);
	printf("TIme = %lld.%06lld seconds\n", diff.tv_sec, diff.tv_usec);

	close(fd);
}
	

int main(int argc, char** argv)
{
	printf("Now testing statically compiled syscalls...\n\n");
	write_tester();
	printf("Returned from syscall tester\n\n");
	
	syscall_eval();
	exit_tester();
	return 0;
}
