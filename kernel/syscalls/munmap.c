#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/memory.h>

int sys_munmap(size_t viraddr, size_t len) {
	uint32_t npages = PAGE_CEIL(len) >> PAGE_BITS;
	int ret;
	size_t phyaddr;

	LOG_INFO("munmap addr 0x%llx, len 0x%llx\n", viraddr, len);

	if (BUILTIN_EXPECT(!viraddr, 0))
		return -EINVAL;
	if (BUILTIN_EXPECT(!len, 0))
		return -EINVAL;

	/* Free virtual address space */
	ret = vma_free((size_t)viraddr, (size_t)viraddr+npages*PAGE_SIZE);

	if(ret < 0) {
		LOG_ERROR("munmap: cannot free VMA\n");
		return ret;
	}

	phyaddr = virt_to_phys((size_t)viraddr);
	if (BUILTIN_EXPECT(!phyaddr, 0))
		return -EFAULT;

	/* Unmap physical pages */
	page_unmap(viraddr, npages);
	if(put_pages(phyaddr, npages) != 0)
		LOG_ERROR("munmap: error releasing physical pages\n");

	return 0;
}
