#include <hermit/syscall.h>
#include <hermit/semaphore.h>

int sys_sem_init(sem_t** sem, unsigned int value)
{
	int ret;

	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	*sem = (sem_t*) kmalloc(sizeof(sem_t));
	if (BUILTIN_EXPECT(!(*sem), 0))
		return -ENOMEM;

	ret = sem_init(*sem, value);
	if (ret) {
		kfree(*sem);
		*sem = NULL;
	}

	return ret;
}

