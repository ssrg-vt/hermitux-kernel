#include <hermit/syscall.h>

int sys_nanosleep(struct timespec *req, struct timespec *rem) {
	/* TODO here I don't take care of rem, I don't think signal interruption
	 * is possible ... */
	unsigned long long int ms = req->tv_sec * 1000 + req->tv_nsec / 1000000;
	sys_msleep(ms);
	return 0;
}

