#include <hermit/syscall.h>
#include <hermit/time.h>

/* This is not a Linux syscall */

size_t sys_get_ticks(void)
{
	return get_clock_tick();
}

