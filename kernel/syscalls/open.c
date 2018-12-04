#include <hermit/syscall.h>
#include <hermit/spinlock.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/logging.h>
#include <hermit/minifs.h>

extern spinlock_irqsave_t lwip_lock;
extern volatile int libc_sd;

typedef struct {
	const char* name;
	int flags;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_open_t;

int sys_open(const char* name, int flags, int mode)
{

	if(unlikely(!name)) {
		LOG_ERROR("open: name is null\n");
		return -EINVAL;
	}

	if (likely(is_uhyve())) {

		if(minifs_enabled)
			return minifs_open(name, flags, mode);

		uhyve_open_t uhyve_open = {(const char*)virt_to_phys((size_t)name), flags, mode, -1};

		uhyve_send(UHYVE_PORT_OPEN, (unsigned)virt_to_phys((size_t) &uhyve_open));

		return uhyve_open.ret;
	}

#ifndef NO_NET

	int s, i, ret, sysnr = __NR_open;
	size_t len;

	spinlock_irqsave_lock(&lwip_lock);
	if (libc_sd < 0) {
		ret = -EINVAL;
		goto out;
	}

	s = libc_sd;
	len = strlen(name)+1;

	//i = 0;
	//lwip_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &i, sizeof(i));

	ret = lwip_write(s, &sysnr, sizeof(sysnr));
	if (ret < 0)
		goto out;

	ret = lwip_write(s, &len, sizeof(len));
	if (ret < 0)
		goto out;

	i=0;
	while(i<len)
	{
		ret = lwip_write(s, name+i, len-i);
		if (ret < 0)
			goto out;
		i += ret;
	}

	ret = lwip_write(s, &flags, sizeof(flags));
	if (ret < 0)
		goto out;

	ret = lwip_write(s, &mode, sizeof(mode));
	if (ret < 0)
		goto out;

	//i = 1;
	//lwip_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &i, sizeof(i));

	lwip_read(s, &ret, sizeof(ret));

out:
	spinlock_irqsave_unlock(&lwip_lock);

	return ret;

#endif /* NO_NET */
	LOG_ERROR("open: network disabled, cannot use qemu isle\n");
	return -ENOSYS;
}

