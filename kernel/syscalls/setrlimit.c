#include <hermit/logging.h>
#include <hermit/syscall.h>

int sys_setrlimit(int resource, const struct rlimit *rlim) {
	LOG_ERROR("setrlimit: syscall not supported\n");
	return -ENOSYS;
}
