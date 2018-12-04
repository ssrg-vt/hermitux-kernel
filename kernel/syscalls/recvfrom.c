#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <lwip/sockets.h>

int hermit_recvfrom(int s, void *mem, size_t len, int flags,
		struct sockaddr *from, socklen_t *fromlen);

int sys_recvfrom(int s, void *mem, size_t len, int flags,
		struct sockaddr *from, socklen_t *fromlen) {
#ifndef NO_NET
	return hermit_recvfrom(s, mem, len, flags, from, fromlen);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */

}
