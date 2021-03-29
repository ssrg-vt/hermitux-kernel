#include <hermit/syscall.h>

extern unsigned long long syscall_boot_tsc;
extern unsigned long long syscall_freq;
extern unsigned long epoch_offset;

inline static unsigned long long t_rdtsc(void)
{
	unsigned int lo, hi;

	asm volatile ("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");

	return ((unsigned long long)hi << 32ULL | (unsigned long long)lo);
}

int sys_time(long *tloc) {

	long sec;

	unsigned long long diff = t_rdtsc() - syscall_boot_tsc;
	sec = diff/syscall_freq;

	sec += epoch_offset;

	if(tloc)
		*tloc = sec;

	return sec;
}
