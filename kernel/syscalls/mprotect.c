#include <hermit/syscall.h>
#include <hermit/logging.h>

long sys_mprotect(size_t addr, size_t len, unsigned long prot) {

	LOG_ERROR("mprotect: unsupported syscall\n");

	/* FIXME */
	return -ENOSYS;
}
