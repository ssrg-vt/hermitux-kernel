#include <hermit/syscall.h>
#include <hermit/logging.h>

long sys_mprotect(size_t addr, size_t len, unsigned long prot) {

	LOG_WARNING("mprotect: unsupported syscall, faking success\n");

	/* FIXME */
	return 0;
}
