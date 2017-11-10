#include <hermit/syscall.h>

static inline int socket_send(int fd, const 	void* buf, size_t len)
{
	int ret, sz = 0;

	do {
		ret = lwip_write(fd, (char*)buf + sz, len-sz);
		if (ret >= 0)
			sz += ret;
		else
			return ret;
	} while(sz < len);

	return len;
}

