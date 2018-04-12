#include <hermit/syscall.h>
#include <hermit/spinlock.h>
#include <hermit/syscall_disabler.h>

#ifdef DISABLE_SYS_READ
#include "read.c"
#endif /* DISABLE_SYS_READ */

extern spinlock_t readwritev_spinlock;

int sys_readv(int fd, const struct iovec *iov, unsigned long vlen) {
	int i, bytes_read, total_bytes_read;

	bytes_read = total_bytes_read = 0;
	
	/* writev is supposed to be atomic */
	spinlock_lock(&readwritev_spinlock);
	for(i=0; i<vlen; i++) {
		bytes_read = sys_read(fd, (char *)(iov[i].iov_base),
				iov[i].iov_len);
		
		if(bytes_read < 0)
			goto out;

		total_bytes_read += bytes_read;
	}

out:
	spinlock_unlock(&readwritev_spinlock);
	return total_bytes_read;
}

