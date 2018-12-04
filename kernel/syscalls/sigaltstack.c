#include <hermit/syscall.h>
#include <hermit/stddef.h>

/* TODO */
long sys_sigaltstack(const stack_t *ss, stack_t *oss) {
	return -ENOSYS;
}
