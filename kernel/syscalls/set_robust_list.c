#include <hermit/syscall.h>
#include <hermit/errno.h>
#include <hermit/logging.h>

long sys_set_robust_list(void *head, size_t len) {
	/* TODO */
	LOG_ERROR("set_robust_list: syscall not supported\n");
	return -ENOSYS;
}
