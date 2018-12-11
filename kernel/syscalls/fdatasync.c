#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <asm/uhyve.h>
#include <hermit/minifs.h>

typedef struct {
	int fd;
	int ret;
} __attribute__((packed)) uhyve_fsync_t;

int sys_fdatasync(int fd) {
	uhyve_fsync_t arg;

	if(minifs_enabled)
		return 0;

	arg.fd = fd;
	arg.ret = -1;

	uhyve_send(UHYVE_PORT_FDATASYNC, (unsigned)virt_to_phys((size_t)&arg));
	return arg.ret;
}
