#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/logging.h>
#include <hermit/minifs.h>

typedef unsigned short umode_t;

typedef struct {
	const char *pathname;
	umode_t mode;
	int ret;
} __attribute__ ((packed)) uhyve_mkdir_t;

int sys_mkdir(const char *pathname,  umode_t mode) {

	if(unlikely(!pathname)) {
		LOG_ERROR("mkdir: pathname is null\n");
		return -EINVAL;
	}

	if(likely(is_uhyve())) {

		if(minifs_enabled)
			return minifs_mkdir(pathname, mode);

		uhyve_mkdir_t args = {(const char *)virt_to_phys((size_t)pathname),
				mode, 0};
		uhyve_send(UHYVE_PORT_MKDIR, (unsigned)virt_to_phys((size_t)&args));
		return args.ret;
	}

	/* qemu not supported yet */
	LOG_ERROR("mkdir: qemu isle not supported\n");
	return -ENOSYS;
}
