#include <hermit/syscall.h>
#include <lwip/sockets.h>
#include <hermit/logging.h>

extern int hermit_setsockopt(int fd, int level, int optname, char *optval,
		socklen_t optlen);

int sys_setsockopt(int fd, int level, int optname, char *optval, socklen_t optlen) {

#ifndef NO_NET
	return hermit_setsockopt(fd, level, optname, optval, optlen);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */
}
