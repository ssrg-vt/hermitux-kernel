#include <asm/stddef.h>
#include <hermit/string.h>
#include <hermit/logging.h>

/* This is not a Linux syscall */

extern char hermitux_hostname[];

int sys_gethostname(char *name, size_t len)
{

	if(unlikely(!name)) {
		LOG_ERROR("gethostname: name is null\n");
		return -EINVAL;
	}

	strncpy(name, hermitux_hostname, len);
	return 0;
}

