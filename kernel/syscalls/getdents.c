#include <hermit/logging.h>
#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <hermit/minifs.h>

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char *d_name;
	char pad;
	char d_type;
};

typedef struct {
	int fd;
	struct linux_dirent *dirp;
	unsigned int count;
	int ret;
} __attribute__((packed)) uhyve_getdeents_t;

int sys_getdents(unsigned int fd, struct linux_dirent *dirp,
		unsigned int count) {

	if(fd & LWIP_FD_BIT)
		return -EINVAL;

	if(minifs_enabled) {
		LOG_ERROR("getdents not supported by minifs\n");
		return -ENOSYS;
	}

	/* The host will write in dirp and we cannot assume it is contiguous in
	 * physical memory so we need to use a physically contiguous temp buffer */
	struct linux_dirent *tmp_dirp = kmalloc(count);
	if(!tmp_dirp)
		return -ENOMEM;

	uhyve_getdeents_t arg = {fd, (void *)virt_to_phys((size_t)tmp_dirp),
		count, -1};
	uhyve_send(UHYVE_PORT_GETDENTS, (unsigned)virt_to_phys((size_t)&arg));

	if(arg.ret < 0)
		goto out;

	memcpy(dirp, tmp_dirp, count);
	kfree(tmp_dirp);

out:
	return arg.ret;
}
