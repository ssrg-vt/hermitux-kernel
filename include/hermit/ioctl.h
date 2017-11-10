#ifndef __IOCTL_H__
#define __IOCTL_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Needed for TIOCGWINSZ */
struct winsize {
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
};

#define TIOCGWINSZ 0x00005413

#ifdef __cplusplus
}
#endif

#endif
