#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

int main(void) {
	struct timeval start, stop, res;

	gettimeofday(&start, NULL);
	sys_msleep(10000);
	gettimeofday(&stop, NULL);

	timersub(&stop, &start, &res);

	printf("%ld.%06ld\n", res.tv_sec, res.tv_usec);

	return 0;
}
