#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <lwip/sockets.h>

#define F_DUPFD  0
#define F_GETFD  1
#define F_SETFD  2
#define F_GETFL  3
#define F_SETFL  4
#define F_GETLK  5
#define F_SETLK  6
#define F_SETLKW 7
#define F_SETOWN 8
#define F_GETOWN 9
#define F_SETSIG 10
#define F_GETSIG 11

#define F_SETOWN_EX 15
#define F_GETOWN_EX 16

#define F_GETOWNER_UIDS 17

extern int hermit_fcntl(int s, int cmd, int val);

typedef struct {
	int fd;
	unsigned int cmd;
	unsigned long arg;
	int ret;
} __attribute__((packed)) uhyve_fcntl_t;


int sys_fcntl(int fd, unsigned int cmd, unsigned long arg) {
	uhyve_fcntl_t u_arg;
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

		switch(cmd) {
			case F_SETFD:
				u_arg.fd = fd;
				u_arg.cmd = cmd;
				u_arg.arg = arg;
				u_arg.ret = -1;
				uhyve_send(UHYVE_PORT_FCNTL, virt_to_phys((size_t)&u_arg));
				return u_arg.ret;

			default:
				LOG_WARNING("fcntl: currently unsupported - faking succes "
					"(fd %d, cmd %d)\n", fd, cmd);
				return 0;

		}

	}
#endif

	LOG_ERROR("fcntl: not supported with qemu isle\n");
	return -ENOSYS;
}

