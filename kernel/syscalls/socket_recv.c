#include <hermit/syscall.h>

static inline int socket_recv(int fd, void* buf, size_t len)
{
	int ret, sz = 0;

	do {
		ret = lwip_read(fd, (char*)buf + sz, len-sz);
		if (ret >= 0)
			sz += ret;
		else
			return ret;
	} while(sz < len);

	return len;
}

