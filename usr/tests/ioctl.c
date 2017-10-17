
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <hermit/ioctl.h>
#include <unistd.h>
#include <hermit/syscall.h>

#define ITERATIONS	10000


inline static unsigned long long rdtsc(void) {
	unsigned long lo, hi;
	asm volatile ("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
	return ((unsigned long long) hi << 32ULL | (unsigned long long) lo);
}

int main(int argc, char** argv)
{
	int i;
	unsigned long long start, stop;
	struct winsize sz;

	start = rdtsc();
	for(i=0; i<ITERATIONS; i++) {
		sys_ioctl(0, TIOCGWINSZ, (unsigned long)&sz);
		(void)sz;
	}
	stop = rdtsc();

	printf("Result: %llu\n", stop - start);

	return 0;
}
