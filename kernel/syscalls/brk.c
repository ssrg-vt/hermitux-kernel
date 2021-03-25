#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>

extern const void kernel_start;

ssize_t sys_brk(ssize_t val) {
	ssize_t ret;
	vma_t* heap = per_core(current_task)->heap;
	static spinlock_t heap_lock = SPINLOCK_INIT;

	if(!val)
		return heap->end;

	if (BUILTIN_EXPECT(!heap, 0)) {
		LOG_ERROR("sys_brk: missing heap!\n");
		do_abort();
	}

	spinlock_lock(&heap_lock);

	ret = heap->end;

	// check heapp boundaries
	if ((val >= HEAP_START) && (val < HEAP_START + HEAP_SIZE)) {
		heap->end = val;

		// reserve VMA regions
		if (PAGE_FLOOR(heap->end) > PAGE_FLOOR(ret)) {
			// region is already reserved for the heap, we have to change the
			// property
			// And also consider a bit more vrtual memory due to over-mapping
			vma_free(PAGE_FLOOR(ret), PAGE_CEIL(heap->end) + PAGE_SIZE * OVERMAP, 0);
			vma_add(PAGE_FLOOR(ret), PAGE_CEIL(heap->end) + PAGE_SIZE * OVERMAP, VMA_HEAP|VMA_USER);
		}

		ret = val;

	} else ret = -ENOMEM;

	// allocation and mapping of new pages for the heap
	// is catched by the pagefault handler

	spinlock_unlock(&heap_lock);

	return ret;

}

