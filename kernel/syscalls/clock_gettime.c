#include <hermit/syscall.h>

int sys_clock_gettime(clockid_t clk_id, struct timespec *tp) {
	/* Disabled for now, musl calls gettimeofday if clock_gettime
	 * returns -ENOSYS */
	return -ENOSYS;
}

