#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/spinlock.h>

extern spinlock_irqsave_t lwip_lock;
extern volatile int libc_sd;
extern spinlock_irqsave_t stdio_lock;

typedef struct {
	int sysnr;
	int fd;
	size_t len;
} __attribute__((packed)) sys_write_t;

typedef struct {
	int fd;
	const char* buf;
	size_t len;
} __attribute__((packed)) uhyve_write_t;

ssize_t sys_write(int fd, const char* buf, size_t len)
{
	if (BUILTIN_EXPECT(!buf, 0))
		return -1;

	if (is_uhyve()) {
		uhyve_write_t uhyve_args = {fd, (const char*) virt_to_phys((size_t) buf), len};

		uhyve_send(UHYVE_PORT_WRITE, (unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.len;
	}

	ssize_t i, ret;
	int s;
	sys_write_t sysargs = {__NR_write, fd, len};

	// do we have an LwIP file descriptor?
	if (fd & LWIP_FD_BIT) {
		ret = lwip_write(fd & ~LWIP_FD_BIT, buf, len);
		if (ret < 0)
			return -errno;

		return ret;
	}

	spinlock_irqsave_lock(&lwip_lock);
	if (libc_sd < 0)
	{
		spinlock_irqsave_unlock(&lwip_lock);

		spinlock_irqsave_lock(&stdio_lock);
		for(i=0; i<len; i++)
			kputchar(buf[i]);
		spinlock_irqsave_unlock(&stdio_lock);

		return len;
	}

	s = libc_sd;
	lwip_write(s, &sysargs, sizeof(sysargs));

	i=0;
	while(i < len)
	{
		ret = lwip_write(s, (char*)buf+i, len-i);
		if (ret < 0) {
			spinlock_irqsave_unlock(&lwip_lock);
			return ret;
		}

		i += ret;
	}

	if (fd > 2) {
		ret = lwip_read(s, &i, sizeof(i));
		if (ret < 0)
			i = ret;
	} else i = len;

	spinlock_irqsave_unlock(&lwip_lock);

	return i;
}

