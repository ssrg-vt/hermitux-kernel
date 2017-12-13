#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/memory.h>

int sys_munmap(size_t viraddr, size_t len) {
	size_t phyaddr;
	uint32_t npages = PAGE_CEIL(len) >> PAGE_BITS;

	if (BUILTIN_EXPECT(!viraddr, 0))
		return -EINVAL;
	if (BUILTIN_EXPECT(!len, 0))
		return -EINVAL;

	phyaddr = virt_to_phys((size_t)viraddr);
	if (BUILTIN_EXPECT(!phyaddr, 0))
		return -ENOMEM;

	vma_free((size_t)viraddr-PAGE_SIZE, (size_t)viraddr+(npages+1)*PAGE_SIZE);
	page_unmap((size_t)viraddr, npages);
	put_pages(phyaddr, npages);

	return 0;
}
