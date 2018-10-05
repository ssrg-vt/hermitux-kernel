#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <lwip/sockets.h>

extern int hermit_sendto(int s, const void *dataptr, size_t size, int flags,
		const struct sockaddr *to, socklen_t tolen);

int sys_sendto(int s, const void *dataptr, size_t size, int flags,
		const struct sockaddr *to, socklen_t tolen) {
#ifndef NO_NET
	return hermit_sendto(s, dataptr, size, flags, to, tolen);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */

}
