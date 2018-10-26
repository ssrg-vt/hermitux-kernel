#include <hermit/syscall.h>
#include <hermit/errno.h>
#include <asm/page.h>
#include <hermit/stddef.h>
#include <hermit/logging.h>
#include <hermit/tasks_types.h>
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

long sys_getrlimit(unsigned int resource, struct rlimit *rlim) {
	long ret = 0;

	if(unlikely(!rlim)) {
		LOG_ERROR("getrlimit: rlim is null\n");
		return -EINVAL;
	}

	switch(resource) {
		case RLIMIT_STACK:
			rlim->rlim_cur = DEFAULT_STACK_SIZE;
			rlim->rlim_max = DEFAULT_STACK_SIZE;
			break;

		case RLIMIT_NPROC:
			rlim->rlim_cur = MAX_TASKS;
			rlim->rlim_max = MAX_TASKS;
			break;

		case RLIMIT_NOFILE:
			rlim->rlim_cur = 0x100000; /* linux limit */
			rlim->rlim_max = 0x100000; /* linux limit */
			break;

		case RLIMIT_AS:
		case RLIMIT_DATA:
			rlim->rlim_cur = (HEAP_START + HEAP_SIZE) - tux_start_address;
			rlim->rlim_max = (HEAP_START + HEAP_SIZE) - tux_start_address;
			break;

		case RLIMIT_NICE:
			{
				task_t *task = per_core(current_task);
				int hermitux_prio = task->prio;

				/* see kernel/syscalls/getpriority.c */
				int linux_prio = linux_prio = -(4* hermitux_prio)/3 + (64/3);
				rlim->rlim_cur = (19 - linux_prio + 1);
				rlim->rlim_max = (19 - (-20) + 1);
				break;
			}

		case RLIMIT_CORE:
			rlim->rlim_cur = 0; /* no core dump creation in hermitux */
			rlim->rlim_max = 0;
			break;

		case RLIMIT_FSIZE:
			rlim->rlim_cur = -1; /* same as default in linux */
			rlim->rlim_max = -1;
			break;

		default:
			LOG_ERROR("getrlimit: unsupported operation %d\n", resource);
			ret = -ENOSYS;
	}

	return ret;
}
