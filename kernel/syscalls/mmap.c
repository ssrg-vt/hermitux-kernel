#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/memory.h>
#include <hermit/mmap_areas.h>

/* We use the concept of 'mmap areas' to track which part of the address space
 * are used for mmap mappings (currently just memory allocation). It is needed
 * to enable on demand virtual to physical mapping for such areas: we check in
 * the page fault handler if the faulty address falls into one of the mmap
 * areas
 */

#define MMAP_AREA_MAX	256

typedef struct s_mmap_area {
	uint64_t addr;
	uint64_t size;
} mmap_area;

static mmap_area *mmap_areas = NULL;
spinlock_irqsave_t mmap_areas_lock = SPINLOCK_IRQSAVE_INIT;

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

	LOG_INFO("add mmap area: %llx -> %llx\n", addr, addr+size);

	spinlock_irqsave_lock(&mmap_areas_lock);

	for(i=0; i<MMAP_AREA_MAX; i++)
		if(mmap_areas[i].size == 0) {
			mmap_areas[i].addr = addr;
			mmap_areas[i].size = size;
			spinlock_irqsave_unlock(&mmap_areas_lock);
			return 0;
		}

	spinlock_irqsave_unlock(&mmap_areas_lock);
	LOG_ERROR("Max amount of mmap areas reached!\n");
	return -1;
}

/* Return 1 if addr corresponds to a mmap mapping */
int mmap_area_check(uint64_t addr) {
	int i;

	LOG_INFO("(%llx) mmap area check for %llx\n", mmap_areas, addr);

	spinlock_irqsave_lock(&mmap_areas_lock);
	for(i=0; i<MMAP_AREA_MAX; i++) {
		if(mmap_areas[i].size)
		LOG_INFO("%llx - %llx\n", mmap_areas[i].addr, mmap_areas[i].addr + 
				mmap_areas[i].size);
		else if(i<10)
			LOG_INFO("%d: 0\n", i);
		if(mmap_areas[i].size && (addr >= mmap_areas[i].addr) &&
				(addr < (mmap_areas[i].addr + mmap_areas[i].size))) {
			spinlock_irqsave_unlock(&mmap_areas_lock);
			return 1;
		}
	}

	spinlock_irqsave_unlock(&mmap_areas_lock);
	return 0;
}

int mmap_area_remove(uint64_t addr) {
	int i;

LOG_INFO("del mmap area: %llx\n", addr);
	spinlock_irqsave_lock(&mmap_areas_lock);
	for(i=0; i<MMAP_AREA_MAX; i++)
		if(mmap_areas[i].addr == addr) {
			mmap_areas[i].size = 0;
			spinlock_irqsave_unlock(&mmap_areas_lock);
			return 0;
		}

	spinlock_irqsave_unlock(&mmap_areas_lock);
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

	/* Indicate the area as used for mmap */
	if(mmap_area_add(viraddr+PAGE_SIZE, len))
		return (size_t)NULL;

	return (size_t) (viraddr+PAGE_SIZE);
}
