#include <hermit/syscall.h>
#include <hermit/signal.h>

int sys_signal(signal_handler_t handler)
{
	return hermit_signal(handler);
}
