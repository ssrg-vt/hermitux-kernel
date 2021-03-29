#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/tasks_types.h>
#include <hermit/tasks.h>
#include <hermit/spinlock.h>

/* Resources identifiers */
#define RLIMIT_CPU 			0
#define RLIMIT_FSIZE		1
#define RLIMIT_DATA			2
#define RLIMIT_STACK		3
#define RLIMIT_CORE			4
#define RLIMIT_RSS			5
#define RLIMIT_NPROC		6
#define RLIMIT_NOFILE		7
#define RLIMIT_MEMLOCK		8
#define RLIMIT_AS			9
#define RLIMIT_LOCKS		10
#define RLIMIT_SIGPENDING	11
#define RLIMIT_MSGQUEUE		12
#define RLIMIT_NICE			13
#define RLIMIT_RTPRIO		14
#define RLIMIT_NLIMITS		15

extern size_t kernel_start;
extern uint64_t tux_start_address;

typedef long long int rlim_t;
struct rlimit {
	rlim_t rlim_cur;
	rlim_t rlim_max;
};

extern task_t task_table[];
extern spinlock_irqsave_t table_lock;

int sys_prlimit64(int pid, unsigned int resource, struct rlimit *new_rlim,
		struct rlimit *old_rlim) {

	if(unlikely(new_rlim)) {
		LOG_ERROR("prlimit64: do not support setting new limits\n");
		return -ENOSYS;
	}

    if(old_rlim) {
        switch(resource) {
            case RLIMIT_STACK:
                old_rlim->rlim_cur = DEFAULT_STACK_SIZE;
                old_rlim->rlim_max = DEFAULT_STACK_SIZE;
                break;

            case RLIMIT_NPROC:
                old_rlim->rlim_cur = MAX_TASKS;
                old_rlim->rlim_max = MAX_TASKS;
                break;

            case RLIMIT_NOFILE:
                old_rlim->rlim_cur = 0x100000; /* linux limit */
                old_rlim->rlim_max = 0x100000; /* linux limit */
                break;

            case RLIMIT_AS:
            case RLIMIT_DATA:
                old_rlim->rlim_cur = (HEAP_START + HEAP_SIZE) - tux_start_address;
                old_rlim->rlim_max = (HEAP_START + HEAP_SIZE) - tux_start_address;
                break;

            case RLIMIT_NICE:
                {
                    int hermitux_prio = -1;

                    if(!pid) {
                        task_t *task = per_core(current_task);
                        hermitux_prio = task->prio;
                    } else {
                        spinlock_irqsave_lock(&table_lock);
                        if(task_table[pid].status != TASK_INVALID)
                            hermitux_prio = task_table[pid].prio;
                        spinlock_irqsave_unlock(&table_lock);
                    }

                    if(hermitux_prio == -1) {
                        LOG_ERROR("prlimit64: could not find task %u\n", pid);
                        return -EINVAL;
                    }

                    /* see kernel/syscalls/getpriority.c */
                    int linux_prio = linux_prio = -(4* hermitux_prio)/3 + (64/3);
                    old_rlim->rlim_cur = (19 - linux_prio + 1);
                    old_rlim->rlim_max = (19 - (-20) + 1);
                    break;
                }

            case RLIMIT_CORE:
                old_rlim->rlim_cur = 0; /* no core dump creation in hermitux */
                old_rlim->rlim_max = 0;
                break;

            case RLIMIT_FSIZE:
                old_rlim->rlim_cur = -1; /* same as default in linux */
                old_rlim->rlim_max = -1;
                break;

            default:
                LOG_ERROR("prlimit64: unsupported operation %d\n", resource);
                return -ENOSYS;
	}

	return -ENOSYS;
}
