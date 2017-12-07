#include <hermit/syscall.h>

int sys_time(long *tloc) {
	struct timeval tv;

	if(sys_gettimeofday(&tv, NULL) != 0)
		return -ENOSYS;

	return tv.tv_sec;
}
