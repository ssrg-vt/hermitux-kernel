#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/memory.h>

int sys_munmap(size_t viraddr, size_t len) {
	uint32_t npages = PAGE_CEIL(len) >> PAGE_BITS;
	int ret;

	if (BUILTIN_EXPECT(!viraddr, 0))
		return -EINVAL;
	if (BUILTIN_EXPECT(!len, 0))
		return -EINVAL;

	/* Free virtual address space */
	ret = vma_free((size_t)viraddr, (size_t)viraddr+npages*PAGE_SIZE, 1);

	if(ret < 0) {
		LOG_ERROR("munmap: cannot free VMA\n");
		return ret;
	}

	return 0;
}
