#include <hermit/syscall.h>

int sys_stat(const char* file, /*struct stat *st*/ void* st)
{
	return -ENOSYS;
}

