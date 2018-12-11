#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <asm/uhyve.h>
#include <hermit/minifs.h>

typedef struct {
	char *path;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_creat_t;

int sys_creat(const char *path, int mode) {
	uhyve_creat_t arg;

	if(minifs_enabled)
		return minifs_creat(path, mode);

	arg.path = (char *)virt_to_phys((size_t)path);
	arg.mode = mode;
	arg.ret = -1;

	uhyve_send(UHYVE_PORT_CREAT, (unsigned)virt_to_phys((size_t)&arg));

	return arg.ret;
}
