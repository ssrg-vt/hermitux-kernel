#include <hermit/syscall.h>

extern int block_current_task(void);

struct pollfd {
	int fd;
	short events;
	short revents;
};

int sys_poll(struct pollfd *ufds, unsigned int nfds, int timeout_msecs) {
    /* FIXME dummy implementation */
    return block_current_task();
}
