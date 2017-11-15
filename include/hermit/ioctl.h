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

/* needed for TCGETS */
#define NCCS	19

typedef unsigned char cc_t;
typedef uint32_t tcflag_t;

struct termios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[NCCS];
};

#define TCGETS 0x00005401

#ifdef __cplusplus
}
#endif

#endif
