#include <hermit/syscall.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>
#include <hermit/minifs.h>
#include <asm/uhyve.h>

extern spinlock_t readwritev_spinlock;

typedef struct {
	int fd;
	char* buf;
        size_t len;
	ssize_t ret;
} __attribute__((packed)) uhyve_read_t;


int sys_readv(int fd, const struct iovec *iov, unsigned long vlen) {
	int i, bytes_read, total_bytes_read;

#ifndef NO_NET
	// do we have an LwIP file descriptor?
	if (fd & LWIP_FD_BIT)
		return -ENOSYS;

#endif

	if(unlikely(!iov)) {
		LOG_ERROR("readv: iov is null\n");
		return -EINVAL;
	}

	bytes_read = total_bytes_read = 0;

	/* readv is supposed to be atomic */
	spinlock_lock(&readwritev_spinlock);
	for(i=0; i<vlen; i++) {

		if(unlikely(!(iov[i].iov_base) && iov[i].iov_len)) {
			LOG_ERROR("readv: vector member %d has null buffer\n", i);
			return -EINVAL;
		}

		if(minifs_enabled && fd > 2)
			bytes_read = minifs_read(fd, iov[i].iov_base, iov[i].iov_len);
		else {
			uhyve_read_t args = {fd,
				(char *) virt_to_phys((size_t)(iov[i].iov_base)),
				iov[i].iov_len};

			uhyve_send(UHYVE_PORT_READ, (unsigned)virt_to_phys((size_t)&args));
			bytes_read = args.ret;
		}

		if(unlikely(bytes_read < 0))
			goto out;

		total_bytes_read += bytes_read;
	}

out:
	spinlock_unlock(&readwritev_spinlock);
	return total_bytes_read;
}

