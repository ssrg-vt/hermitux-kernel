#include <hermit/syscall.h>

int sys_madvise(unsigned long start, size_t len_in, int behavior) {
	return -ENOSYS;
}
