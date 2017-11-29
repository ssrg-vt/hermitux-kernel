#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>

extern spinlock_irqsave_t lwip_lock;
extern volatile int libc_sd;

#ifndef NO_NET

typedef struct {
	int sysnr;
	int fd;
	size_t len;
} __attribute__((packed)) sys_read_t;

#endif /* NO_NET */

typedef struct {
	int fd;
	char* buf;
        size_t len;
	ssize_t ret;
} __attribute__((packed)) uhyve_read_t;

ssize_t sys_read(int fd, char* buf, size_t len)
{
	sys_read_t sysargs = {__NR_read, fd, len};
	ssize_t j, ret;
	int s;

#ifndef NO_NET
	// do we have an LwIP file descriptor?
	if (fd & LWIP_FD_BIT) {
		ret = lwip_read(fd & ~LWIP_FD_BIT, buf, len);
		if (ret < 0)
			return -errno;

		return ret;
	}
#endif

	if (is_uhyve()) {
		uhyve_read_t uhyve_args = {fd, (char*) virt_to_phys((size_t) buf), len, -1};

		uhyve_send(UHYVE_PORT_READ, (unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.ret;
	}

#ifndef NO_NET
	spinlock_irqsave_lock(&lwip_lock);
	if (libc_sd < 0) {
		spinlock_irqsave_unlock(&lwip_lock);
		return -ENOSYS;
	}

	s = libc_sd;
	lwip_write(s, &sysargs, sizeof(sysargs));

	lwip_read(s, &j, sizeof(j));
	if (j > 0)
	{
		ssize_t i = 0;

		while(i < j)
		{
			ret = lwip_read(s, buf+i, j-i);
			if (ret < 0) {
				spinlock_irqsave_unlock(&lwip_lock);
				return ret;
			}

			i += ret;
		}
	}

	spinlock_irqsave_unlock(&lwip_lock);

	return j;

#endif /* NO_NET */
	LOG_ERROR("Network disabled, cannot use qemu isle\n");
	return -ENOSYS;
}

