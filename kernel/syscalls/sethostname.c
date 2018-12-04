#include <asm/stddef.h>
#include <hermit/string.h>
#include <hermit/logging.h>

extern char hermitux_hostname[];
extern size_t hermitux_hostname_len;

int sys_sethostname(char *name, size_t len)
{
	if(unlikely(!name)) {
		LOG_ERROR("sethostname: name is null\n");
		return -EINVAL;
	}

	if(unlikely(len < hermitux_hostname_len)) {
		LOG_WARNING("sethostname: name too big, should be < %u, truncating "
				"name\n, hostname_len");
		len = hermitux_hostname_len;
	}

	strncpy(hermitux_hostname, name, len);
	return 0;
}

