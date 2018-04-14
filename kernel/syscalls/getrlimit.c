#include <hermit/syscall.h>
#include <hermit/errno.h>
#include <asm/page.h>
#include <hermit/stddef.h>

/* Resources identifiers */
#define RLIMIT_CPU 			0
#define RLIMIT_FSZIE		1
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
#define tux_start_address	0x400000

typedef long long int rlim_t;
struct rlimit {
	rlim_t rlim_cur;
	rlim_t rlim_max;
};

long
sys_getrlimit(unsigned int resource, struct rlimit *rlim) {
	long ret = 0;

	switch(resource) {
		case RLIMIT_STACK:
			rlim->rlim_cur = rlim->rlim_max = DEFAULT_STACK_SIZE;
			break;

		case RLIMIT_NPROC:
			rlim->rlim_cur = rlim->rlim_max = MAX_TASKS;
			break;

		case RLIMIT_NOFILE:
			rlim->rlim_cur = rlim->rlim_max = 0x100000; /* linux limit */
			break;

		case RLIMIT_AS:
		case RLIMIT_DATA:
			rlim->rlim_cur = rlim->rlim_max = (HEAP_START + HEAP_SIZE) -
				tux_start_address;
			break;

		default:
			ret = -ENOSYS;
	}
	
	return ret;
}
