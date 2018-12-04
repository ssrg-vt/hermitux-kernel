#include <hermit/syscall.h>
#include <hermit/signal.h>
#include <hermit/tasks_types.h>

int sig_hermit_signal(signal_handler_t handler);

int sys_signal(signal_handler_t handler)
{
	return sig_hermit_signal(handler);
}

int sig_hermit_signal(signal_handler_t handler)
{
	task_t* curr_task = per_core(current_task);
	curr_task->signal_handler = handler;

	return 0;
}

