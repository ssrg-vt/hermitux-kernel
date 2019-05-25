#include <hermit/syscall.h>
#include <hermit/time.h>
#include <asm/processor.h>
#include <hermit/logging.h>
#include <hermit/tasks_types.h>
#include <hermit/tasks.h>

int ns_timer_wait(unsigned int ticks);
void ns_udelay(uint32_t usecs);

/* TODO here I don't take care of rem, I don't think signal interruption
	 * is possible ... */
int sys_nanosleep(struct timespec *req, struct timespec *rem) {
	unsigned long long int ms;

	if(unlikely(!req)) {
		LOG_ERROR("nanosleep: req is null\n");
		return -EINVAL;
	}

	ms = req->tv_sec * 1000 + req->tv_nsec / 1000000;

	if (ms * TIMER_FREQ / 1000 > 0)
		timer_wait(ms * TIMER_FREQ / 1000);
	else if (ms > 0)
		udelay(ms * 1000);
	return 0;
}
