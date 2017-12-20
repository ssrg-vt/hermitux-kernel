#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_openat(int dirfd, const char *pathname, int flags, int mode) {
	
	if(pathname[0] == '/')
		return sys_open(pathname, flags, mode);
	
	return -ENOSYS;
}
