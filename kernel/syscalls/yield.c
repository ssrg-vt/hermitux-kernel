#include <hermit/syscall.h>
#include <hermit/tasks.h>

/* not a Linux syscall */

void sys_yield(void)
{
#if 0
	check_workqueues();
#else
	if (BUILTIN_EXPECT(go_down, 0))
		shutdown_system();
	check_scheduling();
#endif
}

