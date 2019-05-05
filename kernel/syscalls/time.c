#include <hermit/syscall.h>

extern unsigned long long syscall_boot_tsc;
extern unsigned long long syscall_freq;

inline static unsigned long long t_rdtsc(void)
{
	return get_rdtsc();
}

int sys_time(long *tloc) {

	long sec;

	unsigned long long diff = t_rdtsc() - syscall_boot_tsc;
	sec = diff/syscall_freq;

	if(tloc)
		*tloc = sec;

	return sec;
}
