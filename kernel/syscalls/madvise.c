#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_madvise(unsigned long start, size_t len_in, int behavior) {
	LOG_INFO("madvise @%#x\n", start);
	return -ENOSYS;
}
