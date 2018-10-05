#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <lwip/sockets.h>

extern int hermit_fcntl(int s, int cmd, int val);

int sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg) {

#ifndef NO_NET
	if(likely(is_uhyve())) {
		int ret;

		// do we have an LwIP file descriptor?
		if (fd & LWIP_FD_BIT) {
			ret = hermit_fcntl(fd, cmd, arg);
			if (ret < 0)
				return -errno;

			return ret;
		}

		LOG_WARNING("fcntl: currently unsupported - faking succes\n");
		return 0;
	}
#endif

	LOG_ERROR("fcntl: not supported with qemu isle\n");
	return -ENOSYS;
}

