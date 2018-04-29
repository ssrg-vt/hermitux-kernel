#include <hermit/syscall.h>
#include <hermit/tasks_types.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>

typedef unsigned id_t;

#define PRIO_PROCESS 0
#define PRIO_PGRP    1
#define PRIO_USER    2

extern task_t task_table[];
extern spinlock_irqsave_t table_lock;

int sys_setpriority(int which, id_t who, int prio) {
	int hermitux_prio = -1;
	task_t *task;

	if(unlikely(which != PRIO_PROCESS && which != PRIO_PGRP &&
				which != PRIO_USER)) {
		LOG_ERROR("setpriority: 'which' is invalid\n");
		return -EINVAL;
	}

	if(unlikely(prio < -20 || prio > 20)) {
		LOG_ERROR("setpriority: bad value for prio\n");
		return -EINVAL;
	}

	/* Mapping of Linux to Hermitux priorities:
	 * system: (low) ----> (high)
	 * htux:   0 ---------> 31
	 * linux:  20 -------->-20
	 */
	hermitux_prio = -(3*prio)/4 + 16;

	LOG_INFO("setprio:\n");
	LOG_INFO(" LINUX:%d\n", prio);
	LOG_INFO(" HTUX:%d\n", hermitux_prio);

	if(!who) {
		/* Set the priority of the calling process */
		task = per_core(current_task);
		task->prio = hermitux_prio;
	} else {
		int done = 0;
		spinlock_irqsave_lock(&table_lock);
		if(task_table[who].status != TASK_INVALID) {
			done = 1;
			task_table[who].prio = hermitux_prio;
		}
		spinlock_irqsave_unlock(&table_lock);

		if(!done) {
			LOG_ERROR("setpriority: could not find task %u\n", who);
			return -EINVAL;
		}
	}

	return 0;
}

/* TODO remove this ? */
int sys_setprio(tid_t* id, int prio)
{
	return -ENOSYS;
}

