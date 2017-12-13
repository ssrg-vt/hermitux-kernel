#include <hermit/syscall.h>
#include <lwip/sockets.h>
#include <hermit/logging.h>

int sys_bind(int fd, struct sockaddr *addr, int addrlen) {
#ifndef NO_NET
	struct sockaddr_in sa_server;
	struct in_addr addr_local;

	addr_local.s_addr = INADDR_ANY;

	memset((char *) &sa_server, 0x00, sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr = addr_local;

	sa_server.sin_port = htons(8000);
	return lwip_bind(fd, (struct sockaddr *) &sa_server, sizeof(sa_server));
	//return bind(fd, addr, addrlen);
#else
	LOG_ERROR("Network disabled, cannot process bind syscall!\n");
	return -ENOSYS;
#endif /* NO_NET */
}
