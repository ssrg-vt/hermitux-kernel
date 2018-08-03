#include <hermit/syscall.h>
#include <hermit/stddef.h>

/* TODO */
int sys_mincore(unsigned long start, size_t len, unsigned char *vec) {
	return -ENOSYS;
}
