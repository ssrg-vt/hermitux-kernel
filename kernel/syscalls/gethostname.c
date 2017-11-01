#include <asm/stddef.h>
#include <hermit/string.h>

int sys_gethostname(char *name, size_t len)
{
	strncpy(name, "hermit", len);

	return 0;
}

