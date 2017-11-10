#include <hermit/syscall.h>
#include <hermit/spinlock.h>

extern spinlock_t readwritev_spinlock;

int sys_writev(int fd, const struct iovec *iov, unsigned long vlen) {
	int i, bytes_written, total_bytes_written;

	bytes_written = total_bytes_written = 0;
	
	/* writev is supposed to be atomic */
	spinlock_lock(&readwritev_spinlock);
	for(i=0; i<vlen; i++) {
		bytes_written = sys_write(fd, (char *)(iov[i].iov_base),
				iov[i].iov_len);
		
		if(bytes_written < 0)
			goto out;

		total_bytes_written += bytes_written;
	}

out:
	spinlock_unlock(&readwritev_spinlock);
	return total_bytes_written;
}


