#include <hermit/syscall.h>
#include <hermit/signal.h>
#include <hermit/logging.h>
#include <hermit/tasks.h>
#include <hermit/dequeue.h>

extern dequeue_t *signal_queue;

int hermit_sys_kill(tid_t dest, int signum);

int sys_kill(tid_t dest, int signum)
{
	if(signum < 0) {
		return -EINVAL;
	}
	return hermit_sys_kill(dest, signum);
}

int hermit_sys_kill(tid_t dest, int signum)
{
	task_t* task;
	if(BUILTIN_EXPECT(get_task(dest, &task), 0)) {
		LOG_ERROR("Trying to send signal %d to invalid task %d\n", signum, dest);
		return -ENOENT;
	}

	const tid_t dest_core = task->last_core;

	LOG_DEBUG("Send signal %d from task %d (core %d) to task %d (core %d)\n",
	        signum, per_core(current_task)->id, CORE_ID, dest, dest_core);

	if(task == per_core(current_task)) {
		LOG_DEBUG("  Deliver signal to itself, call handler immediately\n");

		if(task->signal_handler) {
			task->signal_handler(signum);
		}
		return 0;
	}

	sig_t signal = {dest, signum};
	if(dequeue_push(&signal_queue[dest_core], &signal)) {
		LOG_ERROR("  Cannot push signal to task's signal queue, dropping it\n");
		return -ENOMEM;
	}

	// send IPI to destination core
	LOG_DEBUG("  Send signal IPI (%d) to core %d\n", SIGNAL_IRQ, dest_core);
	apic_send_ipi(dest_core, SIGNAL_IRQ);

	return 0;
}

