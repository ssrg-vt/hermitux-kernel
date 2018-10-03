#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <lwip/sockets.h>

int sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg) {

	if(likely(is_uhyve())) {

		/* For now only work on sockets -> TODO check if fd is a socket */
		return lwip_fcntl(fd, cmd, arg);

		LOG_WARNING("fcntl: currently unsupported - faking succes\n");
		return 0;
	}

	LOG_ERROR("fcntl: not supported with qemu isle\n");
	return -ENOSYS;
}

