#include <hermit/syscall.h>
#include <hermit/logging.h>

#ifndef NO_NET
#include <lwip/sockets.h>
#endif

int sys_setsockopt(int fd, int level, int optname, char *optval, int optlen) {

#ifndef NO_NET
	return lwip_setsockopt(fd, level, optname, optval, optlen);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */
}
