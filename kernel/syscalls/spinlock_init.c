#include <hermit/syscall.h>
#include <hermit/spinlock.h>

int sys_spinlock_init(spinlock_t** lock)
{
	int ret;

	if (BUILTIN_EXPECT(!lock, 0))
		return -EINVAL;

	*lock = (spinlock_t*) kmalloc(sizeof(spinlock_t));
	if (BUILTIN_EXPECT(!(*lock), 0))
		return -ENOMEM;

	ret = spinlock_init(*lock);
	if (ret) {
		kfree(*lock);
		*lock = NULL;
	}

	return ret;
}

