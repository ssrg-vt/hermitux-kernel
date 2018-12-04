#include <hermit/logging.h>
#include <hermit/syscall.h>

size_t sys_pread64(int fd, void *buf, size_t count, off_t offset) {
	int ret = -1;

	if(fd & LWIP_FD_BIT) {
		LOG_ERROR("pread64 not supported on a socket\n");
		return -ENOSYS;
	}

	/* Save the offset */
	uint64_t prev_offset = sys_lseek(fd, 0x0, SEEK_CUR);
	if(prev_offset == (uint64_t)-1) {
		LOG_ERROR("pread64: cannot get  offset\n");
		return -1;
	}

	/* Set the offset */
	if(sys_lseek(fd, offset, SEEK_SET) == (uint64_t)-1) {
		LOG_ERROR("pread64: cannot set offset\n");
		ret = -1;
		goto out;
	}

	ret = sys_read(fd, buf, count);

	/* Set the offset back */
	if(sys_lseek(fd, prev_offset, SEEK_SET) == (uint64_t)-1) {
		LOG_ERROR("pread64: cannot set back offset\n");
		ret = -1;
		goto out;
	}

out:
	return ret;
}
