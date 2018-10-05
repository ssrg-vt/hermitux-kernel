#include <hermit/syscall.h>
#include <lwip/sockets.h>
#include <hermit/logging.h>

extern int hermit_socket(int domain, int type, int protocol);

int sys_socket(int domain, int type, int protocol) {
	int ret;
#ifndef NO_NET
	ret = hermit_socket(domain, type, protocol);
	return ret;
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */

}
