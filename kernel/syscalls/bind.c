#include <hermit/syscall.h>
#include <lwip/sockets.h>
#include <hermit/logging.h>

int sys_bind(int fd, struct sockaddr *addr, int addrlen) {
#ifndef NO_NET
	return bind(fd, addr, addrlen);
#else
	LOG_ERROR("Network disabled, cannot process bind syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */
}
