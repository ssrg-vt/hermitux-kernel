#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <lwip/sockets.h>
extern int hermit_getsockopt(int s, int level, int optname, void *optval,
		socklen_t *optlen);

int sys_getsockopt(int s, int level, int optname, void *optval,
		socklen_t *optlen) {

#ifndef NO_NET
	return hermit_getsockopt(s, level, optname, optval, optlen);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */

}
