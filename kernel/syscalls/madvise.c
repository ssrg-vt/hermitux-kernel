#include <hermit/syscall.h>
#include <hermit/logging.h>

#define MADV_NORMAL      0
#define MADV_RANDOM      1
#define MADV_SEQUENTIAL  2
#define MADV_WILLNEED    3
#define MADV_DONTNEED    4
#define MADV_FREE        8
#define MADV_REMOVE      9
#define MADV_DONTFORK    10
#define MADV_DOFORK      11
#define MADV_MERGEABLE   12
#define MADV_UNMERGEABLE 13
#define MADV_HUGEPAGE    14
#define MADV_NOHUGEPAGE  15
#define MADV_DONTDUMP    16
#define MADV_DODUMP      17
#define MADV_HWPOISON    100
#define MADV_SOFT_OFFLINE 101

int sys_madvise(unsigned long start, size_t len_in, int behavior) {

	switch(behavior) {
		case MADV_NORMAL:
		case MADV_RANDOM:
		case MADV_SEQUENTIAL:
		case MADV_WILLNEED:
		case MADV_DONTNEED:
			LOG_WARNING("madivse: NORMAL/RANDOM/SEQUENTIAL/WILLNEED/DONTNEED "
					"not supported\n");
			return 0;

		case MADV_DONTFORK:
		case MADV_DOFORK:
			LOG_WARNING("madivse: DO(N)TFORK not supported as we do not "
					"support fork");
			return 0;

		default:
			LOG_ERROR("madvise: unsupported command\n");
			return -ENOSYS;
	}

	/* Should not come here */
	return -ENOSYS;
}
