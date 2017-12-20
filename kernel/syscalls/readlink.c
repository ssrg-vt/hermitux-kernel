#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_readlink(const char *path, char *buf, int bufsiz) {
	LOG_INFO("Readlink %s\n", path);
	return -ENOSYS;
}
