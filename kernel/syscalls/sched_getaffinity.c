#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_sched_getaffinity(int pid, unsigned int len,
		unsigned long *user_mask_ptr) {
	/* FIXME */
	LOG_ERROR("sched_getaffinity: unsupported syscall\n");
	return -ENOSYS;
}
