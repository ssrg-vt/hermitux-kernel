#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <asm/uhyve.h>

typedef struct {
	const char* name;
	int flags;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_open_t;

int sys_openat(int dirfd, const char *pathname, int flags, int mode) {

	if(!pathname) {
		LOG_ERROR("openat: pathname is null\n");
		return -EINVAL;
	}

	if(pathname[0] == '/') {
		if (is_uhyve()) {
			uhyve_open_t uhyve_open = {(const char*)virt_to_phys((size_t)pathname),
				flags, mode, -1};

			uhyve_send(UHYVE_PORT_OPEN,
				(unsigned)virt_to_phys((size_t) &uhyve_open));

			return uhyve_open.ret;
		}

		LOG_ERROR("openat: not supported with qemu isle\n");
		return -ENOSYS;
	}

	LOG_ERROR("openat: only support absolute pathnames\n");
	return -ENOSYS;
}
