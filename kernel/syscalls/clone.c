#include <hermit/syscall.h>
#include <hermit/tasks.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>
#include <hermit/time.h>

/* From Linux sources: */
#define CLONE_VM				0x00000100
#define CLONE_CHILD_CLEARTID	0x00200000
#define CLONE_CHILD_SETTID		0x01000000

extern void __clone_entry(struct state *s);

int sys_clone(unsigned long clone_flags, void *stack, int *ptid, int *ctid,
        void *tls, struct state *state)
{
	tid_t id;

	/* Unikernel -> do no allow new processes creation */
	if(!(clone_flags & CLONE_VM)) {
		LOG_ERROR("clone: unsuported clone method. As a unikernel we do not "
				"support fork and support only thread creation with the "
				"CLONE_VM flag\n");
		return -ENOSYS;
	}

	/* To understand how set/clear_child_tidwork, see the man page for
	 * set_tid_address */
	void *set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? ctid : NULL;
	void *clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? ctid : NULL;

    /* We will restore fs to the right value when returning in the child */
    state->fs = (uint64_t)tls;

	/* clone_task will take care of copyign state on the stack of the created
     * thread and pass it as the parameter of __clone_entry so that we can be
     * reetrant */
    int ret = clone_task(&id, (int(*)(void *))__clone_entry, NULL,
            per_core(current_task)->prio, set_child_tid, clear_child_tid,
            state);

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

