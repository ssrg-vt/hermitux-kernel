#include <hermit/syscall.h>
#include <hermit/logging.h>


int sys_dummy_syscall(void)
{
	//LOG_INFO("In the dummy syscall\n"); 
	return 2468;
}
