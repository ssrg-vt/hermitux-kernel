#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>

typedef unsigned short umode_t;

typedef struct {
	const char *pathname;
	umode_t mode;
	int ret;
} __attribute__ ((packed)) uhyve_mkdir_t;

int sys_mkdir(const char *pathname,  umode_t mode) {
	if(is_uhyve()) {
		uhyve_mkdir_t args = {(const char *)virt_to_phys((size_t)pathname), 
				mode, 0};
		uhyve_send(UHYVE_PORT_MKDIR, (unsigned)virt_to_phys((size_t)&args));
		return args.ret;
	}

	/* qemu not supported yet */
	return -ENOSYS;
}
