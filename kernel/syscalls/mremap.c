#include <hermit/logging.h>
#include <hermit/syscall.h>

#define MAP_FIXED 0x10

size_t sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len,
		unsigned long flags, unsigned long new_addr) {

	uint64_t ret;

	if(flags & MAP_FIXED) {
		LOG_ERROR("mremap: no support for MAP_FIXED\n");
		return -ENOSYS;
	}

	ret = sys_mmap(NULL, new_len, 0x0, flags, 0x0, 0x0);

	memcpy(ret, addr, old_len);

	sys_munmap(addr, old_len);

	return ret;

}
