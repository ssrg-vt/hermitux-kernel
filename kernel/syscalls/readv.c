#include <hermit/syscall.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>

extern spinlock_t readwritev_spinlock;

int sys_readv(int fd, const struct iovec *iov, unsigned long vlen) {
	int i, bytes_read, total_bytes_read;

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

		bytes_read = sys_read(fd, (char *)(iov[i].iov_base),
				iov[i].iov_len);

		if(unlikely(bytes_read < 0))
			goto out;

		total_bytes_read += bytes_read;
	}

out:
	spinlock_unlock(&readwritev_spinlock);
	return total_bytes_read;
}

