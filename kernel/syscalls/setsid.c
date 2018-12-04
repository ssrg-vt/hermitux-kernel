#include <hermit/logging.h>
#include <hermit/syscall.h>

int sys_setsid(void) {
	task_t* task = per_core(current_task);
	return task->id;
}
