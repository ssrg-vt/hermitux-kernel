#include <hermit/syscall.h>
#include <lwip/sockets.h>
#include <hermit/logging.h>
extern int hermit_select(int maxfdp1, fd_set *readset, fd_set *writeset,
		fd_set *exceptset, struct timeval *timeout);

int sys_select(int maxfdp1, fd_set *readset, fd_set *writeset,
		fd_set *exceptset, struct timeval *timeout) {

#ifndef NO_NET
	return hermit_select(maxfdp1, readset, writeset, exceptset, timeout);
#else
	LOG_ERROR("Network disabled, cannot process bind syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */
}
