#include <hermit/logging.h>
#include <hermit/syscall.h>
#include <asm/uhyve.h>

struct linux_dirent64 {
   uint64_t        d_ino;    /* 64-bit inode number */
   uint64_t        d_off;    /* 64-bit offset to next structure */
   unsigned short d_reclen; /* Size of this dirent */
   unsigned char  d_type;   /* File type */
   char           d_name[]; /* Filename (null-terminated) */
};

typedef struct {
	int fd;
	struct linux_dirent64 *dirp;
	unsigned int count;
	int ret;
} __attribute__((packed)) uhyve_getdeents64_t;

int sys_getdents64(unsigned int fd, struct linux_dirent64 *dirp,
		unsigned int count) {

	if(fd & LWIP_FD_BIT)
		return -EINVAL;

	if(minifs_enabled) {
		LOG_ERROR("getdents64 not supported by minifs\n");
		return -ENOSYS;
	}

	/* The host will write in dirp and we cannot assume it is contiguous in
	 * physical memory so we need to use a physically contiguous temp buffer */
	struct linux_dirent64 *tmp_dirp = kmalloc(count);
	if(!tmp_dirp)
		return -ENOMEM;

	uhyve_getdeents64_t arg = {fd, (void *)virt_to_phys((size_t)tmp_dirp),
		count, -1};
	uhyve_send(UHYVE_PORT_GETDENTS64, (unsigned)virt_to_phys((size_t)&arg));

	LOG_INFO("getdents64 returned %d\n", arg.ret);

	if(arg.ret < 0)
		goto out;

	memcpy(dirp, tmp_dirp, count);
	kfree(tmp_dirp);

out:
	return arg.ret;
}
