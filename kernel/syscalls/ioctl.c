#include <hermit/syscall.h>
#include <hermit/ioctl.h>
#include <hermit/logging.h>

int sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg) {
	/* Check cmd, we want that to fail on commands that we did not explore */
	switch(cmd) {
		case TIOCGWINSZ:
			{
				struct winsize *res = (struct winsize *)arg;
				/* Quick hack, FIXME */
				res->ws_row = 24;
				res->ws_col = 80;
				res->ws_xpixel = 0;
				res->ws_ypixel = 0;
				return 0;
			}
		default:
			LOG_ERROR("unsupported ioctl command 0x%x\n", cmd);
			return -ENOSYS;
	}	

	/* should not come here */
	return -1;
}
