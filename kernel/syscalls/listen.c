#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <lwip/sockets.h>

#define SOMAXCONN 512
extern int hermit_listen(int s, int backlog);

int sys_listen(int s, int backlog) {
#ifndef NO_NET
	if(backlog > SOMAXCONN)
		return -EINVAL;
	return hermit_listen(s, backlog);
#else
	LOG_ERROR("Network disabled, cannot process socket syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */

}
