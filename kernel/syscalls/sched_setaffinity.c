#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_sched_setaffinity(int pid, unsigned int len,
		unsigned long *user_mask_ptr) {
	/* FIXME */
	LOG_ERROR("sched_setaffinity: unsupported syscall\n");
	return 0;
}
