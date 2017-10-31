#include <hermit/syscall.h>
#include <hermit/tasks.h>

int sys_clone(tid_t* id, void* ep, void* argv)
{
	return clone_task(id, ep, argv, per_core(current_task)->prio);
}

