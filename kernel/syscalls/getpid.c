#include <hermit/syscall.h>
#include <hermit/tasks_types.h>

tid_t sys_getpid(void)
{
	task_t* task = per_core(current_task);

	return task->id;
}

