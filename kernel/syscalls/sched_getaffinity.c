#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <hermit/tasks_types.h>
#include <hermit/spinlock.h>

/* Code from the musl C Library */
typedef struct cpu_set_t { unsigned long __bits[128/sizeof(long)]; } cpu_set_t;

#define __CPU_op_S(i, size, set, op) ( (i)/8U >= (size) ? 0 : \
			(((unsigned long *)(set))[(i)/8/sizeof(long)] op (1UL<<((i)%(8*sizeof(long))))) )
#define CPU_ZERO_S(size,set) memset((void *)set,0,size)
#define CPU_ZERO(set) CPU_ZERO_S(sizeof(cpu_set_t),set)
#define CPU_SET_S(i, size, set) __CPU_op_S(i, size, set, |=)
#define CPU_SET(i, set) CPU_SET_S(i,sizeof(cpu_set_t),set)

extern task_t task_table[];
extern spinlock_irqsave_t table_lock;

int sys_sched_getaffinity(int pid, unsigned int len,
		unsigned long *user_mask_ptr) {
	cpu_set_t *ptr = (cpu_set_t *)user_mask_ptr;
	int core_id = -1;

	if(unlikely(!user_mask_ptr)) {
		LOG_ERROR("sched_getaffinity: user_mask_ptr is NULL\n");
		return -EINVAL;
	}

	if(!pid) {
		task_t *task = per_core(current_task);
		core_id = task->last_core;
	} else {
		spinlock_irqsave_lock(&table_lock);
		if(task_table[pid].status != TASK_INVALID)
			core_id = task_table[pid].last_core;
		spinlock_irqsave_unlock(&table_lock);
	}

	if(core_id == -1) {
		LOG_ERROR("sched_getaffinity: cannot find task %d\n", pid);
		return -EINVAL;
	}

	CPU_ZERO(ptr);
	CPU_SET(core_id, ptr);

	return 0;
}
