#include <hermit/syscall.h>
#include <hermit/logging.h>

long sys_mprotect(size_t addr, size_t len, unsigned long prot) {

	LOG_WARNING("mprotect: unsupported syscall, faking success, "
            "addr: %p, len: 0x%llx, prot: %d\n", addr, len, prot);

	/* FIXME */
	return 0;
}
