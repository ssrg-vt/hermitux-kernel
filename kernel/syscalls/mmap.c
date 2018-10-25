#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/memory.h>

#define MAP_FIXED 0x10

size_t sys_mmap(unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long fd, unsigned long off) {
	size_t viraddr, phyaddr, bits;
	int err;
	uint32_t npages = PAGE_CEIL(len) >> PAGE_BITS;

	if(flags & MAP_FIXED && (addr % PAGE_SIZE != 0)) {
		LOG_ERROR("mremap: MAP_FIXED needs a page-aligned requested address\n");
		return -EINVAL;
	}

	if (BUILTIN_EXPECT(!len, 0))
		return -EINVAL;

	// get free virtual address space. We get two additional virtual pages
	// to act at guards: they will not be mapped and will protect against
	// overflows
	if(!addr) {
		viraddr = vma_alloc((npages+2)*PAGE_SIZE, VMA_READ | VMA_WRITE |
				VMA_CACHEABLE);
		if (BUILTIN_EXPECT(!viraddr, 0))
			return -ENOMEM;
	} else {
		viraddr = (flags & MAP_FIXED) ? addr-PAGE_SIZE : PAGE_CEIL(addr);
		LOG_INFO("PAGE_CEIL(0x%llx) = 0x%llx\n", addr, viraddr);
		int ret = vma_add(viraddr, viraddr+(npages+2)*PAGE_SIZE,
				VMA_READ | VMA_WRITE | VMA_CACHEABLE);
		if(BUILTIN_EXPECT(ret, 0)) {
			LOG_ERROR("mmap: cannot vma_add!\n");
			return -EFAULT;
		}
	}

	// get physical memory
	phyaddr = get_pages(npages);
	if (BUILTIN_EXPECT(!phyaddr, 0)) {
		vma_free(viraddr, viraddr+(npages+2)*PAGE_SIZE);
		return -ENOMEM;
	}

	bits = PG_RW|PG_GLOBAL|PG_NX;

	// map physical pages to VMA
	err = page_map(viraddr+PAGE_SIZE, phyaddr, npages, bits);
	if (BUILTIN_EXPECT(err, 0)) {
		vma_free(viraddr, viraddr+(npages+2)*PAGE_SIZE);
		put_pages(phyaddr, npages);
		return -EFAULT;
	}

	return (size_t) (viraddr+PAGE_SIZE);
}
