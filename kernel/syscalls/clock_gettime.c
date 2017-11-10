#include <hermit/syscall.h>

int sys_clock_gettime(clockid_t clk_id, struct timespec *tp) {
	struct timeval tv;

	if(sys_gettimeofday(&tv, NULL) != 0)
		return -ENOSYS;
	
	tp->tv_sec = tv.tv_sec;
	tp->tv_nsec = tv.tv_usec * 1000;
	
	return 0;
}

