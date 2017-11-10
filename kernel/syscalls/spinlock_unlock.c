#include <hermit/syscall.h>
#include <hermit/spinlock.h>

int sys_spinlock_unlock(spinlock_t* lock)
{
	if (BUILTIN_EXPECT(!lock, 0))
		return -EINVAL;

	return spinlock_unlock(lock);
}

