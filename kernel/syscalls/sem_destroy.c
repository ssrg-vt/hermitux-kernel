#include <hermit/syscall.h>
#include <hermit/semaphore.h>

int sys_sem_destroy(sem_t* sem)
{
	int ret;

	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	ret = sem_destroy(sem);
	if (!ret)
		kfree(sem);

	return ret;
}

