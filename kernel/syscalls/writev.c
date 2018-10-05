#include <hermit/syscall.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>
#include <hermit/minifs.h>
#include <asm/uhyve.h>

extern spinlock_t readwritev_spinlock;

typedef struct {
	int fd;
	const char* buf;
	size_t len;
} __attribute__((packed)) uhyve_write_t;

int sys_writev(int fd, const struct iovec *iov, unsigned long vlen) {
	int i, bytes_written, total_bytes_written;

#ifndef NO_NET
	// do we have an LwIP file descriptor?
	if (fd & LWIP_FD_BIT) {
		return -ENOSYS;
	}

#endif

	if(unlikely(!iov)) {
		LOG_ERROR("writev: iov is null\n");
		return -EINVAL;
	}

	if(unlikely(!is_uhyve())) {
		LOG_ERROR("writev: only supported with uhyve isle\n");
		return -ENOSYS;
	}

	bytes_written = total_bytes_written = 0;

	/* writev is supposed to be atomic */
	spinlock_lock(&readwritev_spinlock);
	for(i=0; i<vlen; i++) {

		if(unlikely(!(iov[i].iov_base) && iov[i].iov_len)) {
			LOG_ERROR("writev: vector member %d base is null (len=%u)\n", i,
					iov[i].iov_len);
			return -EINVAL;
		}

		if(minifs_enabled && fd > 2)
			bytes_written = minifs_write(fd, iov[i].iov_base, iov[i].iov_len);
		else {
			uhyve_write_t args = {fd,
				(const char *) virt_to_phys((size_t)(iov[i].iov_base)),
				iov[i].iov_len};

			uhyve_send(UHYVE_PORT_WRITE, (unsigned)virt_to_phys((size_t)&args));
			bytes_written = args.len;
		}

		if(bytes_written < 0)
			goto out;

		total_bytes_written += bytes_written;
	}

out:
	spinlock_unlock(&readwritev_spinlock);
	return total_bytes_written;
}


