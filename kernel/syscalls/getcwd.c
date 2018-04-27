#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>

typedef struct {
	char *buf;
	size_t size;
	int ret;
} __attribute__ ((packed)) uhyve_getcwd_t;

int sys_getcwd(char *buf, size_t size) {

	if(unlikely(!buf || size == 0)) {
		LOG_ERROR("getcwd: buf is null or size is zero\n");
		return -EINVAL;
	}

	if(likely(is_uhyve())) {
		uhyve_getcwd_t uhyve_args = {(char *)virt_to_phys((size_t)buf), size, -1};
		uhyve_send(UHYVE_PORT_GETCWD, (unsigned)virt_to_phys((size_t)&uhyve_args));
		return uhyve_args.ret;
	}

	/* Qemu not supported yet */
	return -ENOSYS;

}
