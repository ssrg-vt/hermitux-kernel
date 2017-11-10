#include <hermit/syscall.h>
#include <hermit/time.h>
#include <asm/processor.h>

void sys_msleep(unsigned int ms)
{
	if (ms * TIMER_FREQ / 1000 > 0)
		timer_wait(ms * TIMER_FREQ / 1000);
	else if (ms > 0)
		udelay(ms * 1000);
}

