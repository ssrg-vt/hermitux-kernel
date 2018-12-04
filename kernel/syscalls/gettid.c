#include <hermit/syscall.h>
#include <hermit/tasks_types.h>

int sys_gettid(void)
{
	task_t* task = per_core(current_task);

	return task->id;
}

