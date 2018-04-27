#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>

typedef struct {
	const char *pathname;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_access_t;

int sys_access(const char *pathname, int mode) {

	if(is_uhyve()) {
		uhyve_access_t uhyve_args = {(const char*) virt_to_phys((size_t) pathname),
			mode, -1};
		uhyve_send(UHYVE_PORT_ACCESS, (unsigned)virt_to_phys((size_t)&uhyve_args));
		return uhyve_args.ret;
	}

	/* Qemu not supported for now */
	LOG_ERROR("Syscall not supported with qemu: access\n");
	return -ENOSYS;
}
