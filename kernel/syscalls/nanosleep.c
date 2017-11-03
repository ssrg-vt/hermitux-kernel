#include <hermit/syscall.h>
#include <hermit/time.h>
#include <asm/processor.h>

int sys_nanosleep(struct timespec *req, struct timespec *rem) {
	/* TODO here I don't take care of rem, I don't think signal interruption
	 * is possible ... */
	unsigned long long int ms = req->tv_sec * 1000 + req->tv_nsec / 1000000;

	if (ms * TIMER_FREQ / 1000 > 0)
		timer_wait(ms * TIMER_FREQ / 1000);
	else if (ms > 0)
		udelay(ms * 1000);
	return 0;
}

