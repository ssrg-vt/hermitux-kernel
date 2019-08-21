#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/minifs.h>

typedef struct {
    int dirfd;
	const char *pathname;
	int mode;
	int ret;
    int flags;
} __attribute__((packed)) uhyve_faccessat_t;

int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {

	if(minifs_enabled) {
		LOG_ERROR("faccessat not supported by minifs\n");
		return -ENOSYS;
	}

	if(unlikely(!pathname)) {
		LOG_ERROR("faccessat: pathname is null\n");
		return -EINVAL;
	}

	if(likely(is_uhyve())) {
		uhyve_faccessat_t uhyve_args = {dirfd,
            (const char*) virt_to_phys((size_t) pathname), mode, -1, flags};
		uhyve_send(UHYVE_PORT_FACCESSAT,
                (unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.ret;
	}

	/* Qemu not supported for now */
	LOG_ERROR("Syscall not supported with qemu: access\n");
	return -ENOSYS;
}
