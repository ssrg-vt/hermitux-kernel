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
	off_t offset;
	int whence;
} __attribute__((packed)) sys_lseek_t;

#endif /* NO_NET */

typedef struct {
	int fd;
	off_t offset;
	int whence;
} __attribute__((packed)) uhyve_lseek_t;

off_t sys_lseek(int fd, off_t offset, int whence)
{
	if (is_uhyve()) {
		uhyve_lseek_t uhyve_lseek = { fd, offset, whence };

		outportl(UHYVE_PORT_LSEEK, (unsigned)virt_to_phys((size_t) &uhyve_lseek));

		return uhyve_lseek.offset;
	}

#ifndef NO_NET
	off_t off;
	sys_lseek_t sysargs = {__NR_lseek, fd, offset, whence};
	int s;

	spinlock_irqsave_lock(&lwip_lock);

	if (libc_sd < 0) {
		spinlock_irqsave_unlock(&lwip_lock);
		return -ENOSYS;
	}

	s = libc_sd;
	lwip_write(s, &sysargs, sizeof(sysargs));
	lwip_read(s, &off, sizeof(off));

	spinlock_irqsave_unlock(&lwip_lock);

	return off;
#endif /* NO_NET */

	LOG_ERROR("lseek: network disabled, cannot use qemu isle\n");
	return -ENOSYS;
}

