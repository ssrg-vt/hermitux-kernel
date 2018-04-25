#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_prlimit64(int pid, unsigned int resource, void *new_rlim, void *old_rlim) {
	return -ENOSYS;
}
