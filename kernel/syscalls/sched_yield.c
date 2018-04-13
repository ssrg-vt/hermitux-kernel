#include <hermit/syscall.h>

int sys_sched_yield(void) {
	sys_yield();
	return 0;
}
