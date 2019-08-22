#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/logging.h>
#include <hermit/minifs.h>

typedef unsigned short umode_t;

typedef struct {
    int dirfd;
	const char *pathname;
	umode_t mode;
	int ret;
} __attribute__ ((packed)) uhyve_mkdirat_t;

int sys_mkdirat(int dirfd, const char *pathname,  umode_t mode) {

	if(unlikely(!pathname)) {
		LOG_ERROR("mkdirat: pathname is null\n");
		return -EINVAL;
	}

	if(likely(is_uhyve())) {

		if(minifs_enabled) {
            LOG_ERROR("mkdirat: not supported by minifs\n");
			return -ENOSYS;
        }

		uhyve_mkdirat_t args = {dirfd,
            (const char *)virt_to_phys((size_t)pathname), mode, 0};
		uhyve_send(UHYVE_PORT_MKDIRAT, (unsigned)virt_to_phys((size_t)&args));
		return args.ret;
	}

	/* qemu not supported yet */
	LOG_ERROR("mkdirat: qemu isle not supported\n");
	return -ENOSYS;
}
