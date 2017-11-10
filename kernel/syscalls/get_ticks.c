#include <hermit/syscall.h>
#include <hermit/time.h>

size_t sys_get_ticks(void)
{
	return get_clock_tick();
}

