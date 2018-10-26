#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/memory.h>

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
	int err;
	uint32_t alloc_flags;
	uint32_t npages = PAGE_CEIL(len) >> PAGE_BITS;

	LOG_INFO("mmap addr 0x%llx, len 0x%llx\n", addr, len);

	if(!(flags & MAP_PRIVATE)) {
		LOG_ERROR("mmap: non-private mapping are not supported\n");
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

	/* get free virtual address space */
	if(!addr) {
		viraddr = vma_alloc(npages*PAGE_SIZE, alloc_flags);
		if (BUILTIN_EXPECT(!viraddr, 0))
			return -ENOMEM;
	} else {
		viraddr = (flags & MAP_FIXED) ? addr : PAGE_CEIL(addr);
		int ret = vma_add(viraddr, viraddr+npages*PAGE_SIZE, alloc_flags);

		/* FIXME: when the application requests an already mapped range of
		 * virtual memory, the kernel is supposed to unmap the part that is
		 * requested and remap it to satisfy the current mmap request. We
		 * just fail miserably for now */
		if(BUILTIN_EXPECT(ret, 0)) {
			LOG_ERROR("mmap: cannot vma_add, probably vma range (0x%llx - "
					"0x%llx) requested is already used\n", viraddr,
					viraddr+npages*PAGE_SIZE);
			return -EFAULT;
		}
	}

	/* get physical memory */
	phyaddr = get_pages(npages);
	if (BUILTIN_EXPECT(!phyaddr, 0)) {
		vma_free(viraddr, viraddr+npages*PAGE_SIZE);
		return -ENOMEM;
	}

	bits = PG_GLOBAL;
	if(!(flags & PROT_EXEC)) bits |= PG_NX;
	if(flags & PROT_WRITE) bits |= PG_RW;

	/* map physical pages to VMA */
	err = page_map(viraddr, phyaddr, npages, bits);
	if (BUILTIN_EXPECT(err, 0)) {
		vma_free(viraddr, viraddr+npages*PAGE_SIZE);
		put_pages(phyaddr, npages);
		return -EFAULT;
	}

out:

	/* Emulate a private file mapping */
	if(fd && fd != (int)-1)
		if(map_file(fd, (void *)viraddr, off, len))
			return -EFAULT;

	return (size_t)viraddr;
}

/* Read into address addr the file fd starting from offset in the file, for len
 * bytes */
int map_file(int fd, void *addr, size_t offset, size_t len) {
	int ret = -1;
	size_t old_offset;

	/* save old offset */
	old_offset = sys_lseek(fd, 0x0, SEEK_CUR);
	if(old_offset == -1) {
		LOG_ERROR("mmap: cannot lseek in file (fd %d)\n", fd);
		goto out;
	}

	/* Set the asked offset */
	sys_lseek(fd, offset, SEEK_SET);

	/* Read the file in memory */
	if(sys_read(fd, addr, len) != len) {
		LOG_ERROR("mmap: cannot read file\n");
		goto out;
	}

	/* restore old offset */
	sys_lseek(fd, old_offset, SEEK_SET);
	ret = 0;

out:
	return ret;
}
