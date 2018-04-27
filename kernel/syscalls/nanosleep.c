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
		ns_timer_wait(ms * TIMER_FREQ / 1000);
	else if (ms > 0)
		udelay(ms * 1000);
	return 0;
}

int ns_timer_wait(unsigned int ticks)
{
	uint64_t eticks = per_core(timer_ticks) + ticks;

	task_t* curr_task = per_core(current_task);

	if (curr_task->status == TASK_IDLE)
	{
		/*
		 * This will continuously loop until the given time has
		 * been reached
		 */
		while (per_core(timer_ticks) < eticks) {
			check_workqueues();

			// recheck break condition
			if (per_core(timer_ticks) >= eticks)
				break;

			PAUSE;
		}
	} else if (per_core(timer_ticks) < eticks) {
		check_workqueues();

		if (per_core(timer_ticks) < eticks) {
			set_timer(eticks);
			reschedule();
		}
	}

	return 0;
}

void ns_udelay(uint32_t usecs)
{
	if (has_rdtscp()) {
		uint64_t diff, end, start = rdtscp(NULL);
		uint64_t deadline = get_cpu_frequency() * usecs;

		do {
			end = rdtscp(NULL);
			rmb();
			diff = end > start ? end - start : start - end;
			if ((diff < deadline) && (deadline - diff > 50000))
				check_workqueues();
		} while(diff < deadline);
	} else {
		uint64_t diff, end, start = rdtsc();
		uint64_t deadline = get_cpu_frequency() * usecs;

		do {
			mb();
			end = rdtsc();
			diff = end > start ? end - start : start - end;
			if ((diff < deadline) && (deadline - diff > 50000))
				check_workqueues();
		} while(diff < deadline);
	}
}
