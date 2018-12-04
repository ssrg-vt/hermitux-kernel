#include <hermit/syscall.h>
#include <hermit/logging.h>

#define BUF_SIZE	1024

size_t sys_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
	char buf[BUF_SIZE];
	uint64_t bytes_sent = 0;
	int ret = -1;
	uint64_t prev_offset = 0;

	if(offset) {
		/* Save the old offset for in_fd. It is not needed for out_fd as, if it
		 * is a file (and not a socket), it is normal for sendfile to update its
		 * offset */
		uint64_t prev_offset = sys_lseek(in_fd, 0x0, SEEK_CUR);
		if(prev_offset == (uint64_t)-1) {
			LOG_ERROR("sendfile: cannot get in_fd offset\n");
			return -1;
		}

		/* Set the offset */
		if(sys_lseek(in_fd, *offset, SEEK_SET) == (uint64_t)-1) {
			LOG_ERROR("sendfile: cannot set offset\n");
			ret = -1;
			goto out;
		}
	}

	while(count) {
		int bytes_read = sys_read(in_fd, buf, BUF_SIZE);
		if(bytes_read < 0) {
			LOG_ERROR("sendfile: issue reading\n");
			ret = -1;
			goto out;
		}

		int bytes_written = sys_write(out_fd, buf, bytes_read);
		if(bytes_written < 0) {
			LOG_ERROR("sendfile: issue writing\n");
			ret = -1;
			goto out;
		}

		bytes_sent += bytes_written;
		count -= bytes_written;

		if(bytes_read < BUF_SIZE)
			break;
	}

	/* restore offset for in_fd */
	if(offset) {
		uint64_t end_offset = sys_lseek(in_fd, 0x0, SEEK_CUR);
		*offset = end_offset;
		sys_lseek(in_fd, prev_offset, SEEK_SET);
	}

out:
	return ret;
}
