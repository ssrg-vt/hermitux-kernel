#include <hermit/syscall.h>

int sys_getegid(void) {
	return sys_getgid();
}
