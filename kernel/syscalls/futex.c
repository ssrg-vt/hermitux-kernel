#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/atomic.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

#define FUTEX_PRIVATE_FLAG		128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

int sys_futex(int *uaddr, int futex_op, int val, const struct timespec *timeout,
		int *uaddr2, int val3) {

	int cmd = futex_op & FUTEX_CMD_MASK;

	if(unlikely(!uaddr)) {
		LOG_ERROR("futex: uaddr is null\n");
		return -EINVAL;
	}

	/* Terrible hack here: some library, such as libiomp, will make a first
	 * call to futex to check if it is supported by the system and if not
	 * use some other internal locking mechanism. So in such cases here we just
	 * return -ENOSYS and we are good. Other libraries such as musl require
	 * futex to be supported, and we can get have some simple multithreaded
	 * programs working without a full-fledged futex implementation. However,
	 * we cannot return -ENOSYS in that case. So what we do here is: if there
	 * is too much calls to futex (musl), change from returning -ENOSYS to
	 * the hacky implementation.
	 */
	static int futex_cnt = 0;

	if(futex_cnt++ < 128)
		return -ENOSYS;

	if(futex_op & FUTEX_PRIVATE_FLAG)
		return -ENOSYS;

	switch(cmd) {
		case FUTEX_WAIT:
			/* LOG_INFO("Futex wait on 0x%x @0x%llx\n", val, uaddr); */
			if(*uaddr != val)
				return -EAGAIN;

			/* hack */
			return -ETIMEDOUT;

			break;

		case FUTEX_WAKE:
			/* LOG_INFO("Futex wake %d tasks @0x%llx\n", val, uaddr); */

			/* hack */
			return 1;

			break;

		default:
			LOG_ERROR("Unsupported futex operation\n");
			return -ENOSYS;
	}
	return -ENOSYS;
}

