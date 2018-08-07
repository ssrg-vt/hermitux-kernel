#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/stddef.h>
#include <hermit/minifs.h>

typedef struct {
	char *path;
	char* buf;
	int bufsz;
	ssize_t ret;
} __attribute__((packed)) uhyve_readlink_t;

int sys_readlink(char *path, char *buf, int bufsiz) {

	if(minifs_enabled) {
		LOG_ERROR("readlink currently not supported with minifs\n");
		return -ENOSYS;
	}

	if(unlikely(!path || !buf)) {
		LOG_ERROR("readlink: path or buf is null\n");
		return -EINVAL;
	}

	if (likely(is_uhyve())) {
		uhyve_readlink_t args = {path, (char*) virt_to_phys((size_t) buf),
			bufsiz, -1};

		uhyve_send(UHYVE_PORT_READLINK, (unsigned)virt_to_phys((size_t)&args));

		return args.ret;
	}

	LOG_INFO("readlink: not supported with qemu isle\n");
	return -ENOSYS;
}
