#include <hermit/syscall.h>

long sys_mprotect(size_t addr, size_t len, unsigned long prot) {
	/* FIXME */
	return -ENOSYS;
}
