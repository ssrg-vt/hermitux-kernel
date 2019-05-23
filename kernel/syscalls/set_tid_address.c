#include <hermit/syscall.h>
#include <hermit/logging.h>

long sys_set_tid_address(int *tidptr) {
	task_t* curr_task = per_core(current_task);
	curr_task->clear_child_tid = tidptr;

	return curr_task->id;
}
