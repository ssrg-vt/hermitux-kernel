#include <lwip/sockets.h>
#include <hermit/hermitux_syscalls.h>
#include <hermit/logging.h>
#include <hermit/processor.h>

extern unsigned int get_cpufreq(void);
static unsigned long long start_tsc;
static unsigned long long freq = 0;

inline static unsigned long long gtod_rdtsc(void)
{
	unsigned int lo, hi;

	asm volatile ("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");

	return ((unsigned long long)hi << 32ULL | (unsigned long long)lo);
}

void gettimeofday_init(void) {
	start_tsc = gtod_rdtsc();
	freq = get_cpu_frequency() * 1000000ULL;
}

int sys_gettimeofday(struct timeval *tv, struct timezone *tz) {

	if(tz) {
		LOG_ERROR("gettimeofday: tz should be null\n");
		return -EINVAL;
	}

	if(tv) {
		unsigned long long diff = gtod_rdtsc() - start_tsc;
		tv->tv_sec = diff/freq;
		tv->tv_usec = ((diff - tv->tv_sec * freq) * 1000000ULL) / freq;
		return 0;
	}

	LOG_ERROR("gettimeofday: tv is null\n");
	return -EINVAL;
}
