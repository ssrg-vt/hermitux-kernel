#include <hermit/syscall.h>
#include <lwip/sockets.h>

ssize_t sys_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen) {
	return lwip_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
