#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <lwip/sockets.h>

extern int hermit_connect(int s, const struct sockaddr *name, socklen_t namelen);

int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

#ifndef NO_NET
	return hermit_connect(sockfd, addr, addrlen);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */

}
