#include <hermit/syscall.h>
#include <hermit/semaphore.h>

int sys_sem_post(sem_t* sem)
{
	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	return sem_post(sem);
}

