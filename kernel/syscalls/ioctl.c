#include <hermit/syscall.h>
#include <hermit/ioctl.h>
#include <hermit/logging.h>
#include <hermit/stdio.h>
#include <hermit/errno.h>

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

		case TCGETS: 
			{
				/* TODO that's super ugly, I'm mimicing what linux reports me */
				struct termios *res = (struct termios *)arg;
				res->c_iflag = 0x4500;
				res->c_oflag = 0x5;
				res->c_cflag = 0xbf;
				res->c_lflag = 0x8a3b;
				res->c_line = 0x0;
				res->c_cc[0] = 0x3;
				res->c_cc[1] = 0x1c;
				res->c_cc[2] = 0x7f;
				res->c_cc[3] = 0x15;
				res->c_cc[4] = 0x4;
				res->c_cc[5] = 0x0;
				res->c_cc[6] = 0x1;
				res->c_cc[7] = 0x0;
				res->c_cc[8] = 0x11;
				res->c_cc[9] = 0x13;
				res->c_cc[10] = 0x1a;
				res->c_cc[11] = 0x0;
				res->c_cc[12] = 0x12;
				res->c_cc[13] = 0xf;
				res->c_cc[14] = 0x17;
				res->c_cc[15] = 0x16;
				res->c_cc[16] = 0x0;
				res->c_cc[17] = 0x0;
				res->c_cc[18] = 0x0;

				return 0;
			}

		default:
			LOG_ERROR("unsupported ioctl command 0x%x\n", cmd);
			return -ENOSYS;
	}	

	/* should not come here */
	return -1;
}
