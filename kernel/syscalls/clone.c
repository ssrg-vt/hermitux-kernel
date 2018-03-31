#include <hermit/syscall.h>
#include <hermit/tasks.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>
#include <hermit/time.h>

/* From Linux sources: */
#define CLONE_VM	0x00000100

int sys_clone(unsigned long clone_flags, void *stack, int *ptid, int *ctid, void *arg,
		void *ep)
{
	tid_t id;

	/* Unikernel -> do no allow new processes creation */
	if(!(clone_flags & CLONE_VM))
		return -ENOSYS;

	int ret = clone_task(&id, ep, arg, per_core(current_task)->prio, arg);

	if(ret)
		return ret;

	*(unsigned int *)ctid = id;

	return id;
}

