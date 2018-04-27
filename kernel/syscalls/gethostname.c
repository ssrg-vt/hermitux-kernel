#include <asm/stddef.h>
#include <hermit/string.h>

/* This is not a Linux syscall */

extern char hermitux_hostname[];

int sys_gethostname(char *name, size_t len)
{
	strncpy(name, hermitux_hostname, len);
	return 0;
}

