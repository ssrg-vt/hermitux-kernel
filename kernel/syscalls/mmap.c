#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/memory.h>
#include <hermit/vma.h>

#define MAP_FIXED 		0x10
#define MAP_PRIVATE 	0x02

#define PROT_NONE      0
#define PROT_READ      1
#define PROT_WRITE     2
#define PROT_EXEC      4

int map_file(int fd, void *addr, size_t offset, size_t len);

size_t sys_mmap(unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long fd, unsigned long off) {
	size_t viraddr, phyaddr, bits;
	int err, ret;
	uint32_t alloc_flags;
	uint32_t npages = PAGE_CEIL(len) >> PAGE_BITS;

	if(!(flags & MAP_PRIVATE)) {
		LOG_ERROR("mmap: non-private mappings are not supported\n");
		return -ENOSYS;
	}

	if(flags & MAP_FIXED && (addr % PAGE_SIZE != 0)) {
		LOG_ERROR("mremap: MAP_FIXED needs a page-aligned requested address\n");
		return -EINVAL;
	}

	if (BUILTIN_EXPECT(!len, 0))
		return -EINVAL;

	alloc_flags = VMA_CACHEABLE;
	if(flags & PROT_READ) alloc_flags |= VMA_READ;
	if(flags & PROT_WRITE) alloc_flags |= VMA_WRITE;
	if(flags & PROT_EXEC) alloc_flags |= VMA_EXECUTE;

	ret = 0;
	if(!addr) {
		do {
			/* non-fixed mapping are randomized, ~34 bits of entropy */
			addr = (HEAP_START + HEAP_SIZE) +
				rdrand() % (0x800000000000 - (len + HEAP_START + HEAP_SIZE));
			viraddr = PAGE_FLOOR(addr);
		} while(vma_add(viraddr, viraddr + npages*PAGE_SIZE, alloc_flags));
	} else {
		viraddr = (flags & MAP_FIXED) ? addr : PAGE_FLOOR(addr);
		ret = vma_add(viraddr, viraddr + npages*PAGE_SIZE, alloc_flags);
	}

	/* When the application requests an already mapped range of
	 * virtual memory, the kernel is supposed to unmap the part that is
	 * requested and remap it to satisfy the current mmap request. */
	if(BUILTIN_EXPECT(ret, 0)) {
		if(vma_free(viraddr, viraddr+npages*PAGE_SIZE, 1)) {
			LOG_ERROR("mmap: can't free overlap with previous mapping!\n");
			return -EFAULT;
		}

		if(vma_add(viraddr, viraddr+npages*PAGE_SIZE, alloc_flags) != 0) {
			LOG_ERROR("mmap: cannot vma_add, probably vma range (0x%llx - "
				"0x%llx) requested is already used\n", viraddr,
				viraddr+npages*PAGE_SIZE);
			return -EFAULT;
		}
	}

	/* get physical memory */
	phyaddr = get_pages(npages);
	if (BUILTIN_EXPECT(!phyaddr, 0)) {
		vma_free(viraddr, viraddr+npages*PAGE_SIZE, 0);
		return -ENOMEM;
	}

	/* FIXME: manage flags correctly */
	bits = PG_GLOBAL | PG_PRESENT | PG_RW;

	/* map physical pages to VMA */
	err = page_map(viraddr, phyaddr, npages, bits);
	if (BUILTIN_EXPECT(err, 0)) {
		vma_free(viraddr, viraddr+npages*PAGE_SIZE, 0);
		put_pages(phyaddr, npages);
		return -EFAULT;
	}

	/* Emulate a private file mapping */
	if(fd && (int)fd != -1)
		if(map_file(fd, (void *)viraddr, off, len))
			return -EFAULT;

	return (size_t)viraddr;
}

/* Read into address addr the file fd starting from offset in the file, for len
 * bytes */
int map_file(int fd, void *addr, size_t offset, size_t len) {
	int bytes_read, ret = -1;
	size_t old_offset;

	/* save old offset */
	old_offset = sys_lseek(fd, 0x0, SEEK_CUR);
	if(old_offset == -1) {
		LOG_ERROR("mmap: cannot get offset of file (fd %d)\n", fd);
		goto out;
	}

	/* Set the asked offset */
	if(sys_lseek(fd, offset, SEEK_SET) != offset) {
		LOG_ERROR("mmap: cannot lseek in file (fd %d)\n", fd);
		goto out;
	}

	/* Read the file in memory */
	bytes_read = sys_read(fd, addr, len);
	if(bytes_read < 0) {
		/* It is actually OK to read less bytes that requested because one may
		 * want to mmap a file within a area that is bigger than the file
		 * itself */
		LOG_ERROR("mmap: cannot read file (read returns %d)\n", bytes_read);
		goto out;
	}

	/* restore old offset */
	sys_lseek(fd, old_offset, SEEK_SET);
	ret = 0;

out:
	return ret;
}
