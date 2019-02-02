#include <hermit/syscall.h>
#include <hermit/logging.h>

long sys_set_tid_address(int *tidptr) {
	// TODO
	return (long)tidptr;
}
