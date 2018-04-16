#include "uhyve-profiler.h"

#define _DEFAULT_SOURCE /* for usleep */

#include <linux/kvm.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>

#include "uhyve.h"

#define PROFILER_IRQ_NUM	1 /* will trigger irq 33 in the kernel */
#define PROF_OUTPUT_FILE	"hermitux-prof.txt"
#define PROF_VERBOSE

volatile sig_atomic_t profiling_thread_done = 0;
static pthread_t thread;
static int samples_per_second;
extern int vmfd;
extern uint8_t* mboot;
extern uint8_t* guest_mem;
extern char htux_bin[];
extern char htux_kernel[];
static int wokeup_times = 0;

static void *profiling_thread_fn(void *arg) {
	int usleep_time = 1000000/samples_per_second;
	struct kvm_irq_level irq = {PROFILER_IRQ_NUM, 1};

	while(!profiling_thread_done) {
		usleep(usleep_time);

		wokeup_times++;

		irq.level = 1;
		kvm_ioctl(vmfd, KVM_IRQ_LINE, &irq);
		irq.level = 0;
		kvm_ioctl(vmfd, KVM_IRQ_LINE, &irq);
	}
}

int uhyve_profiler_init(int sample_freq) {

	if(!sample_freq)
		return -1;

	samples_per_second = sample_freq;
	if(pthread_create(&thread, NULL, profiling_thread_fn, NULL)) {
		fprintf(stderr, "Cannot create profiling thread\n");
		return -1;
	}

	return 0;
}

int uhyve_profiler_exit(void) {
	uint64_t tux_samples, tux_samples_num, i;
	char kernel_abs_path[PATH_MAX+1], binary_abs_path[PATH_MAX+1];
	FILE *f;

	profiling_thread_done = 1;
	if(pthread_join(thread, NULL)) {
		fprintf(stderr, "Error joining profiling thread\n");
		return -1;
	}

	tux_samples =  *((uint64_t*) (mboot + 0xD1));
	tux_samples_num =  *((uint64_t*) (mboot + 0xD9));

	f = fopen(PROF_OUTPUT_FILE, "w+");
	if(!f) {
		fprintf(stderr, "Could not open profiler output file\n");
		return -1;
	}

	if(!realpath(htux_bin, binary_abs_path) ||
			!realpath(htux_kernel, kernel_abs_path)) {
		fprintf(stderr, "Profiler cannot resolve absolute paths\n");
		return -1;
	}

	fprintf(f, "bin:%s\n", binary_abs_path);
	fprintf(f, "kernel:%s\n", kernel_abs_path);

	for(i=0; i<tux_samples_num; i++)
		fprintf(f, "%llx\n", ((uint64_t *)(guest_mem + tux_samples))[i]);

#ifdef PROF_VERBOSE
	printf("HermiTux profiler: woke up %u times to gather samples, wrote "
			"results in %s\n", wokeup_times, PROF_OUTPUT_FILE);

#endif

	fclose(f);

	return 0;
}
