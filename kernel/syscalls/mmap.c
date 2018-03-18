#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/memory.h>
#include <hermit/mmap_areas.h>

#define MMAP_AREA_MAX	256

typedef struct s_mmap_area {
	uint64_t addr;
	uint64_t size;
} mmap_area;

static mmap_area *mmap_areas = NULL;

int mmap_areas_init() {
	int i;

	mmap_areas = kmalloc(MMAP_AREA_MAX * sizeof(mmap_area));
	if(!mmap_areas) {
		LOG_ERROR("Cannot init mmap area\n");
		return -1;
	}

	for(i=0; i<MMAP_AREA_MAX; i++)
		mmap_areas[i].size = 0; /* Use size = 0 to indicate free slot */

	return 0;
}

static int mmap_area_add(uint64_t addr, uint64_t size) {
	int i;

	for(i=0; i<MMAP_AREA_MAX; i++)
		if(mmap_areas[i].size == 0) {
			mmap_areas[i].addr = addr;
			mmap_areas[i].size = size;
			return 0;
		}

	LOG_ERROR("Max amount of mmap areas reached!\n");
	return -1;
}

int mmap_area_check(uint64_t addr) {
	int i;

	for(i=0; i<MMAP_AREA_MAX; i++) {
		if(mmap_areas[i].size && (addr >= mmap_areas[i].addr) && (addr < (mmap_areas[i].addr + mmap_areas[i].size)))
			return 1;
	}
	return 0;
}

int mmap_area_remove(uint64_t addr) {
	int i;

	for(i=0; i<MMAP_AREA_MAX; i++)
		if(mmap_areas[i].addr == addr) {
			mmap_areas[i].size = 0;
			return 0;
		}

	LOG_ERROR("Cannot find mmap_area to remove @0x%x\n", addr);
	return -1;

}

size_t sys_mmap(unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long fd, unsigned long off) {
	size_t viraddr;
	uint32_t npages = PAGE_CEIL(len) >> PAGE_BITS;

	if(addr != 0) {
		LOG_ERROR("Request mmap to specific address\n");
		return -ENOSYS;
	}

	if (BUILTIN_EXPECT(!len, 0))
		return (size_t)NULL;

	// get free virtual address space
	viraddr = vma_alloc((npages+2)*PAGE_SIZE, VMA_READ|VMA_WRITE|VMA_CACHEABLE);
	if (BUILTIN_EXPECT(!viraddr, 0))
		return (size_t)NULL;

	if(mmap_area_add(viraddr+PAGE_SIZE, len))
		return (size_t)NULL;

	return (size_t) (viraddr+PAGE_SIZE);
}
