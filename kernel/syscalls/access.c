#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_access(const char *pathname, int mode) {
	/* FIXME */
	LOG_INFO("received access on %s\n", pathname);
	return 0;
}
