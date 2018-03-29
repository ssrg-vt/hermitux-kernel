#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/atomic.h>
#include <hermit/tasks_types.h>
#include <hermit/spinlock.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

#define FUTEX_PRIVATE_FLAG		128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

int sys_futex(int *uaddr, int futex_op, int val, const struct timespec *timeout,
		int *uaddr2, int val3) {

	int cmd = futex_op & FUTEX_CMD_MASK;
	switch(cmd) {
		case FUTEX_WAIT:
			LOG_INFO("Futex wait on 0x%x @0x%llx\n", val, uaddr);
			break;

		case FUTEX_WAKE:
			LOG_INFO("Futex wake %d tasks @0x%llx\n", val, uaddr);
			break;

		default:
			LOG_ERROR("Unsupported futex operation\n");
			return -ENOSYS;
	}
	return -ENOSYS;
}

