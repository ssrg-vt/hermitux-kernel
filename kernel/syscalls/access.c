#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/errno.h>
#include <hermit/minifs.h>

typedef struct {
	const char *pathname;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_access_t;

int sys_access(const char *pathname, int mode) {

	if(minifs_enabled) {
		LOG_ERROR("access not supported by minifs\n");
		return -ENOSYS;
	}

	if(unlikely(!pathname)) {
		LOG_ERROR("access: pathname is null\n");
		return -EINVAL;
	}

	if(likely(is_uhyve())) {
		uhyve_access_t uhyve_args = {(const char*) virt_to_phys((size_t) pathname),
			mode, -1};
		uhyve_send(UHYVE_PORT_ACCESS, (unsigned)virt_to_phys((size_t)&uhyve_args));
		return uhyve_args.ret;
	}

	/* Qemu not supported for now */
	LOG_ERROR("Syscall not supported with qemu: access\n");
	return -ENOSYS;
}
