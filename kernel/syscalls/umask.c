#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_umask(int mask) {
	return mask & 0777;
}
