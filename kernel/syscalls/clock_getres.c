#include <hermit/syscall.h>
#include <lwip/sockets.h>
#include <hermit/hermitux_syscalls.h>
#include <hermit/logging.h>
#include <hermit/processor.h>

#define CLOCK_REALTIME           0
#define CLOCK_MONOTONIC          1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3
#define CLOCK_MONOTONIC_RAW      4
#define CLOCK_REALTIME_COARSE    5
#define CLOCK_MONOTONIC_COARSE   6
#define CLOCK_BOOTTIME           7
#define CLOCK_REALTIME_ALARM     8
#define CLOCK_BOOTTIME_ALARM     9
#define CLOCK_SGI_CYCLE         10
#define CLOCK_TAI               11

int sys_clock_getres(clockid_t id, struct timespec *tp) {

	if(id != CLOCK_REALTIME && id != CLOCK_REALTIME_COARSE &&
		id != CLOCK_MONOTONIC && id != CLOCK_REALTIME_COARSE &&
		id != CLOCK_MONOTONIC_RAW && id != CLOCK_BOOTTIME &&
		id != CLOCK_PROCESS_CPUTIME_ID) {
			LOG_ERROR("clock_getres: unsupported clock id %d\n", id);
			return -ENOSYS;
	}

	if(unlikely(!tp)) {
		LOG_ERROR("clocK_getres: tp is null\n");
		return -EINVAL;
	}

	/* For now we have a stupid clock_gettime implementation so the resolution
	 * is 1000 nsec */
	tp->tv_sec = 0;
	tp->tv_nsec = 1000;

	return 0;
}
