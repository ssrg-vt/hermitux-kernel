#include <hermit/syscall.h>
#include <hermit/tasks_types.h>
#include <hermit/logging.h>
#include <hermit/spinlock.h>

typedef unsigned id_t;

#define PRIO_PROCESS 0
#define PRIO_PGRP    1
#define PRIO_USER    2

extern task_t task_table[];
extern spinlock_irqsave_t table_lock;

int sys_getpriority(int which, id_t who) {
	task_t *task;
	int hermitux_prio = -1;
	long linux_prio = -21;

	if(which != PRIO_PROCESS && which != PRIO_PGRP && which != PRIO_USER) {
		LOG_ERROR("getpriority: 'which' is invalid\n");
		return -EINVAL;
	}

	if(!who) {
		/* Return the priority of the calling process */
		task = per_core(current_task);
		hermitux_prio = task->prio;
	} else {
		spinlock_irqsave_lock(&table_lock);
		if(task_table[who].status != TASK_INVALID)
			hermitux_prio = task_table[who].prio;
		spinlock_irqsave_unlock(&table_lock);
	}

	if(hermitux_prio == -1) {
		LOG_ERROR("getpriority: could not find task %u\n", who);
		return -EINVAL;
	}

	/* Mapping of Hermitux to Linux priorities:
	 * system: (low) ----> (high)
	 * htux:   0 ---------> 31
	 * linux:  20 -------->-20
	 */
	linux_prio = -(4* hermitux_prio)/3 + (64/3);

	/* as done by Linux, avoid returning a negative value and convert nice
	 * value [19,-20] to rlimit style value [1,40]. The C library will take care
	 * of translating it back */
	return (19 - linux_prio + 1);
}

/* TODO: remove this ? */
int sys_getprio(tid_t* id)
{
	task_t* task;

	if(!id) {
		LOG_ERROR("getprio: id is null\n");
		return -EINVAL;
	}

	task = per_core(current_task);

	if (!id || (task->id == *id))
		return task->prio;

	return -EINVAL;
}

