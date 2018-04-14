#include <hermit/syscall.h>
#include <hermit/errno.h>

long
sys_get_robust_list(int pid, void *head_ptr, size_t *len_ptr) {
	/* TODO */
	return -ENOSYS;
}
