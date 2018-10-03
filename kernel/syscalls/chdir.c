#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_chdir(const char *path) {
	LOG_WARNING("chdir not implemented, faking success\n");
	return 0;
}
