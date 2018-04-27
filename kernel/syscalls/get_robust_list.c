#include <hermit/syscall.h>
#include <hermit/errno.h>
#include <hermit/logging.h>

long sys_get_robust_list(int pid, void *head_ptr, size_t *len_ptr) {

	if(!head_ptr || !len_ptr) {
		LOG_ERROR("get_robust_list: some parameter(s) is (are) null\n");
		return -EINVAL;
	}

	LOG_ERROR("get_robust_list: unsuported syscall\n");

	/* TODO */
	return -ENOSYS;
}
