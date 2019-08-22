#include <hermit/syscall.h>
#include <hermit/spinlock.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/logging.h>
#include <hermit/minifs.h>

typedef struct {
    int dirfd;
	const char* pathname;
    int flags;
	int ret;
} __attribute__((packed)) uhyve_unlinkat_t;

int sys_unlinkat(int dirfd, const char *pathname, int flags) {

	if(unlikely(!pathname)) {
		LOG_ERROR("unlinkat: pathname is null\n");
		return -EINVAL;
	}

	if(is_uhyve()) {

		if(minifs_enabled) {
            LOG_ERROR("unlinkat: minifs not supported\n");
            return -ENOSYS;
        }

		uhyve_unlinkat_t uhyve_args = { dirfd,
            (const char *) virt_to_phys((size_t) pathname), flags, 0};
		uhyve_send(UHYVE_PORT_UNLINKAT,
                (unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.ret;
	}

	LOG_ERROR("unlinkat: cannot use with qemu isle\n");
	return -ENOSYS;
}

