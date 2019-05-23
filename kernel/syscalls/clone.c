#include <hermit/syscall.h>
#include <hermit/tasks.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>
#include <hermit/time.h>

/* From Linux sources: */
#define CLONE_VM				0x00000100
#define CLONE_CHILD_CLEARTID	0x00200000
#define CLONE_CHILD_SETTID		0x01000000

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

	/* To understand how set/clear_child_tidwork, see the man page for
	 * set_tid_address */
	void *set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? ctid : NULL;
	void *clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? ctid : NULL;
	int ret = clone_task(&id, ep, arg, per_core(current_task)->prio, arg,
			set_child_tid, clear_child_tid);

	if(ret)
		return ret;

	if(ptid)
		*(unsigned int *)ptid = id;

	/* TODO this is probably not the responsibility of the kernel */
	if(clone_flags & CLONE_CHILD_SETTID)
		if (ctid)
			*(int *)ctid = id;

	return id;
}

