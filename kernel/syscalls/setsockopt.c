#include <hermit/syscall.h>
#include <lwip/sockets.h>
#include <hermit/logging.h>

int sys_setsockopt(int fd, int level, int optname, char *optval, int optlen) {

#ifndef NO_NET
	return setsockopt(fd, level, optname, optval, optlen);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */
}
