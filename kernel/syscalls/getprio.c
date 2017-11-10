#include <hermit/syscall.h>
#include <hermit/tasks_types.h>

int sys_getprio(tid_t* id)
{
	task_t* task = per_core(current_task);

	if (!id || (task->id == *id))
		return task->prio;
	return -EINVAL;
}

