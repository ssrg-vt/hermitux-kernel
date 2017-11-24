#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>

typedef struct {
	char *buf;
	size_t size;
	int ret;
} __attribute__ ((packed)) uhyve_getcwd_t;

int sys_getcwd(char *buf, size_t size) {

	if(is_uhyve()) {
		uhyve_getcwd_t uhyve_args = {(char *)virt_to_phys((size_t)buf), size, -1};
		uhyve_send(UHYVE_PORT_GETCWD, (unsigned)virt_to_phys((size_t)&uhyve_args));
		return uhyve_args.ret;
	}

	/* Qemu not supported yet */
	return -ENOSYS;
	
}
