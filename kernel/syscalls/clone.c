#include <hermit/syscall.h>
#include <hermit/tasks.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>
#include <hermit/time.h>

extern task_t *task_table;
extern spinlock_irqsave_t table_lock;
extern readyqueues_t *readyqueues;

int clone_task(tid_t* id, entry_point_t ep, void* arg, uint8_t prio);

//int sys_clone(tid_t* id, void* ep, void* argv)
int sys_clone(int (*func)(void *), void *stack, int flags, void *arg, int ptid, void *tls)
{
	tid_t id;
	LOG_INFO("Clone EP=0x%x\n", func);
	return clone_task(&id, func, arg, per_core(current_task)->prio);
}


