#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/stddef.h>
#include <hermit/minifs.h>

typedef struct {
    int dirfd;
	char *path;
	char* buf;
	int bufsz;
	ssize_t ret;
} __attribute__((packed)) uhyve_readlinkat_t;

int sys_readlinkat(int dirfd, const char *path, char *buf, int bufsiz) {

	if(minifs_enabled) {
		LOG_ERROR("readlinkat (%s) currently not supported with minifs\n",
				path);
		return -ENOSYS;
	}

	if(unlikely(!path || !buf)) {
		LOG_ERROR("readlinkat: path or buf is null\n");
		return -EINVAL;
	}

	if (likely(is_uhyve())) {
		/* Let's get a physically contiguous buffer to avoid any issue with
		 * the host filling it */
		char *phys_buf = kmalloc(bufsiz);
		if(!phys_buf)
			return -ENOMEM;

		uhyve_readlinkat_t args = {dirfd, (char *)virt_to_phys((size_t) path),
            (char*) virt_to_phys((size_t) phys_buf), bufsiz, -1};

		uhyve_send(UHYVE_PORT_READLINKAT,
                (unsigned)virt_to_phys((size_t)&args));
		memcpy(buf, phys_buf, bufsiz);

		kfree(phys_buf);
		return args.ret;
	}

	LOG_INFO("readlinkat: not supported with qemu isle\n");
	return -ENOSYS;
}
