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
	if(!(clone_flags & CLONE_VM)) {
		LOG_ERROR("clone: unsuported clone method. As a unikernek we do not "
				"support fork and support only thread creation with the "
				"CLONE_VM flag\n");
		return -ENOSYS;
	}

	if(!ep) {
		LOG_ERROR("clone: called with no valid entry point\n");
		return -EINVAL;
	}

	int ret = clone_task(&id, ep, arg, per_core(current_task)->prio, arg);

	if(ret)
		return ret;

	if(ctid)
		*(unsigned int *)ctid = id;

	return id;
}

