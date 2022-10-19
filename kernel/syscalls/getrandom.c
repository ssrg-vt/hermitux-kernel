#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_getrandom(void *buf, unsigned long int buflen, unsigned int flags) {
	LOG_WARNING("syscall getrandom (318) unsupported, faking\n");	
	return 0;
}

