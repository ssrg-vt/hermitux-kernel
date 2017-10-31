#include <hermit/syscall.h>
#include <hermit/signal.h>

int sys_kill(tid_t dest, int signum)
{
	if(signum < 0) {
		return -EINVAL;
	}
	return hermit_kill(dest, signum);
}

