#include "uhyve-profiler.h"

#include <linux/kvm.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include "uhyve.h"

#define PROFILER_IRQ_NUM	1 /* will trigger irq 33 in the kernel */

volatile sig_atomic_t profiling_thread_done = 0;
static pthread_t thread;
static int samples_per_second;
extern int vmfd;

void *profiling_thread_fn(void *arg) {
	int usleep_time = 1000000/samples_per_second;
	struct kvm_irq_level irq = {PROFILER_IRQ_NUM, 1};

	while(!profiling_thread_done) {
		usleep(usleep_time);
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

	profiling_thread_done = 1;
	if(pthread_join(thread, NULL)) {
		fprintf(stderr, "Error joining profiling thread\n");
		return -1;
	}

	return 0;
}
