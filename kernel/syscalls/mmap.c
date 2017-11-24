#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>

extern const void kernel_start;

int sys_mmap(unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long fd, unsigned long off) {
	ssize_t ret;
	vma_t* heap = per_core(current_task)->heap;
	static spinlock_t heap_lock = SPINLOCK_INIT;

	/* simple implementation just for memory allocation for now */
	if(addr != 0 || fd != -1)
		return -ENOSYS;

	if (BUILTIN_EXPECT(!heap, 0)) {
		LOG_ERROR("sys_sbrk: missing heap!\n");
		do_abort();
	}

	spinlock_lock(&heap_lock);

	size_t val = heap->end + len;
	LOG_INFO("new heap request: %#x\n", len);
	ret = heap->end;

	// check heapp boundaries
	if ((val >= HEAP_START) && (val < HEAP_START + HEAP_SIZE)) {
		heap->end = val;

		// reserve VMA regions
		if (PAGE_FLOOR(heap->end) > PAGE_FLOOR(ret)) {
			// region is already reserved for the heap, we have to change the
			// property
			vma_free(PAGE_FLOOR(ret), PAGE_CEIL(heap->end));
			vma_add(PAGE_FLOOR(ret), PAGE_CEIL(heap->end), VMA_HEAP|VMA_USER);
		}

	} else ret = -ENOMEM;

	// allocation and mapping of new pages for the heap
	// is catched by the pagefault handler

	spinlock_unlock(&heap_lock);

	return ret;

}
