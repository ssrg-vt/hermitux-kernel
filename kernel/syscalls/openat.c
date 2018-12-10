#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <asm/uhyve.h>

typedef struct {
	int dirfd;
	const char* name;
	int flags;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_openat_t;

int sys_openat(int dirfd, const char *pathname, int flags, int mode) {

	if(unlikely(!pathname)) {
		LOG_ERROR("openat: pathname is null\n");
		return -EINVAL;
	}

	if(minifs_enabled) {
		LOG_ERROR("openat: unsupported with minifs\n");
		return -ENOSYS;
	}

	if (likely(is_uhyve())) {
		uhyve_openat_t arg = {dirfd,
			(const char *)virt_to_phys((size_t)pathname), flags, mode, -1};
		uhyve_send(UHYVE_PORT_OPENAT, virt_to_phys((size_t)&arg));

		return arg.ret;

	} else {
		LOG_ERROR("openat: not supported with qemu isle\n");
		return -ENOSYS;
	}

	LOG_ERROR("openat: only support absolute pathnames (asked %s)\n",
			pathname);
	return -ENOSYS;
}
