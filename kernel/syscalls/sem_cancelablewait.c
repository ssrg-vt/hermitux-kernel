#include <hermit/syscall.h>
#include <hermit/semaphore.h>

int sys_sem_cancelablewait(sem_t* sem, unsigned int ms)
{
	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	return sem_wait(sem, ms);
}

