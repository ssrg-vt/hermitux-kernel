#include <hermit/syscall.h>

int sys_sched_getaffinity(int pid, unsigned int len, 
		unsigned long *user_mask_ptr) {
	/* FIXME */
	return -ENOSYS;
}
