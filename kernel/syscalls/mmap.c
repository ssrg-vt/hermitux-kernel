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

	if(addr != 0) {
		LOG_ERROR("Request mmap to specific address\n");
		return -ENOSYS;
	}

	if(flags & MAP_FIXED) {
		LOG_ERROR("mremap: no support for MAP_FIXED\n");
		return -ENOSYS;
	}

	if (BUILTIN_EXPECT(!len, 0))
		return -EINVAL;

	// get free virtual address space
	viraddr = vma_alloc((npages+2)*PAGE_SIZE, VMA_READ|VMA_WRITE|VMA_CACHEABLE);
	if (BUILTIN_EXPECT(!viraddr, 0))
		return -ENOMEM;

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
