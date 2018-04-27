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

extern unsigned int get_cpufreq(void);
static unsigned long long start_tsc;
static unsigned long long freq = 0;

inline static unsigned long long cgt_rdtsc(void)
{
	unsigned int lo, hi;

	asm volatile ("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");

	return ((unsigned long long)hi << 32ULL | (unsigned long long)lo);
}

void clock_gettime_init(void) {
	start_tsc = cgt_rdtsc();
	freq = get_cpu_frequency() * 1000000ULL;
}

int sys_clock_gettime(clockid_t id, struct timespec *tp) {

	if(id != CLOCK_REALTIME && id != CLOCK_REALTIME_COARSE &&
		id != CLOCK_MONOTONIC && id != CLOCK_REALTIME_COARSE &&
		id != CLOCK_MONOTONIC_RAW && id != CLOCK_BOOTTIME &&
		id != CLOCK_PROCESS_CPUTIME_ID) {
			LOG_ERROR("clock_gettime: unsupported clock id\n");
			return -ENOSYS;
	}

	if(likely(tp)) {
		unsigned long long diff = cgt_rdtsc() - start_tsc;
		tp->tv_sec = diff/freq;
		tp->tv_nsec = ((diff - tp->tv_sec * freq) * 1000000000ULL) / freq;
	} else {
		LOG_ERROR("clock_gettime: timespec parameter is NULL\n");
		return -EINVAL;
	}

	return 0;
}
