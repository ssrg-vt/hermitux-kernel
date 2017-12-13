#include <hermit/syscall.h>
#include <lwip/sockets.h>
#include <hermit/logging.h>

int sys_socket(int domain, int type, int protocol) {

#ifndef NO_NET
	return lwip_socket(domain, type, protocol);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */

}
