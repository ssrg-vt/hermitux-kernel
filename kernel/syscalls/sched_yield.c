#include <hermit/syscall.h>
#include <hermit/tasks.h>

int sys_sched_yield(void) {

#if 0
	check_workqueues();
#else
	if (BUILTIN_EXPECT(go_down, 0))
		shutdown_system();
	check_scheduling();
#endif

	return 0;
}
