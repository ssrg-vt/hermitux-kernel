#include <hermit/syscall.h>
#include <hermit/errno.h>
#include <hermit/logging.h>

char *ptr = NULL;

/* Fake implementation */
long sys_set_robust_list(void *head, size_t len) {
	/* TODO */
	LOG_WARNING("set_robust_list: syscall not supported, faking success\n");
	ptr = head;
	return 0;
}
