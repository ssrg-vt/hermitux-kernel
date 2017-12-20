#include <hermit/syscall.h>

int sys_geteuid(void) {
	return sys_getuid();
}
