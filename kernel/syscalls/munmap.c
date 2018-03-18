#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/memory.h>
#include <hermit/mmap_areas.h>

extern int check_pagetables(size_t vaddr);

int sys_munmap(size_t viraddr, size_t len) {
	size_t phyaddr;
	uint32_t npages = PAGE_CEIL(len) >> PAGE_BITS;
	int i;

	if (BUILTIN_EXPECT(!viraddr, 0))
		return -EINVAL;
	if (BUILTIN_EXPECT(!len, 0))
		return -EINVAL;

	vma_free((size_t)viraddr-PAGE_SIZE, (size_t)viraddr+(npages+1)*PAGE_SIZE);

	/* Unmap only the pages that have actually been mapped */
	for(i=0; i<npages; i++) {
		size_t page_addr = viraddr + i * PAGE_SIZE;
		if(check_pagetables(page_addr)) {
			size_t phys_addr = virt_to_phys(page_addr);
			page_unmap(page_addr, 1);
			put_page(phys_addr);
		}
	}

	/* Indicate the area as not used anymore */
	mmap_area_remove(viraddr);

	return 0;
}
