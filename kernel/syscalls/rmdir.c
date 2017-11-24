#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>

typedef struct {
	const char *pathname;
	int ret;
} __attribute__ ((packed)) uhyve_rmdir_t;

int sys_rmdir(const char *pathname) {

	if(is_uhyve()) {
		uhyve_rmdir_t args = {(const char *)virt_to_phys((size_t)pathname), 0};
		uhyve_send(UHYVE_PORT_RMDIR, (unsigned)virt_to_phys((size_t)&args));
		return args.ret;
	}

	/* not implemented for qemu yet */
	return -ENOSYS;
}
