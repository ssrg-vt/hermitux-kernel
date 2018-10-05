#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <lwip/sockets.h>

extern int hermit_shutdown(int socket, int how);

int sys_shutdown(int socket, int how) {
#ifndef NO_NET
	return hermit_shutdown(socket, how);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */

}
