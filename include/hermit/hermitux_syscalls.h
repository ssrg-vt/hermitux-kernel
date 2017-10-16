#ifndef HERMITUX_SYSCALLS_H
#define HERMITUX_SYSCALLS_H

typedef int clockid_t;		/* for clock_gettime */

typedef long time_t;		/* for clock_gettime */

struct timespec {			/* for clock_gettime */
	time_t	tv_sec;
	long	tv_nsec;
};

struct timezone {			/* for gettimeofday */
	int tz_minuteswest;
	int tz_dsttime;
};

#endif /* HERMITUX_SYSCALLS_H */
