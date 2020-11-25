#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/logging.h>
#include <hermit/minifs.h>

typedef struct {
    int *filedes;
    int ret;
} uhyve_pipe_t;

int sys_pipe(int *filedes)
{
	if(minifs_enabled) {
		LOG_ERROR("pipe: not supported with minifs\n");
		return -ENOSYS;
	}

	if(unlikely(!filedes)) {
		LOG_ERROR("pipe: called with null argument\n");
		return -EINVAL;
	}

	if(likely(is_uhyve())) {
		uhyve_pipe_t uhyve_args = {(int *)virt_to_phys((size_t)filedes), -1 };

		uhyve_send(UHYVE_PORT_PIPE,
				(unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.ret;
	}

	/* qemu not supported yet */
	LOG_ERROR("pipe: not supported with qemu isle\n");
	return -ENOSYS;
}

