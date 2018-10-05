#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <lwip/sockets.h>

int hermit_accept(int s, struct sockaddr *addr, socklen_t *addrlen);

int sys_accept(int s, struct sockaddr *addr, socklen_t *addrlen) {
#ifndef NO_NET
	return hermit_accept(s, addr, addrlen);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */

}
