#include <hermit/syscall.h>

extern unsigned long long syscall_boot_tsc;
extern unsigned long long syscall_freq;

inline static unsigned long long t_rdtsc(void)
{
#ifdef __aarch64__
#warning "Implementation is missing"

	return 0;
#else
	unsigned int lo, hi;

	asm volatile ("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");

	return ((unsigned long long)hi << 32ULL | (unsigned long long)lo);
#endif
}

int sys_time(long *tloc) {

	long sec;

	unsigned long long diff = t_rdtsc() - syscall_boot_tsc;
	sec = diff/syscall_freq;

	if(tloc)
		*tloc = sec;

	return sec;
}
