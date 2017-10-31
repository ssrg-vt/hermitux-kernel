#include <hermit/syscall.h>
#include <hermit/spinlock.h>

int sys_spinlock_destroy(spinlock_t* lock)
{
	int ret;

	if (BUILTIN_EXPECT(!lock, 0))
		return -EINVAL;

	ret = spinlock_destroy(lock);
	if (!ret)
		kfree(lock);

	return ret;
}

