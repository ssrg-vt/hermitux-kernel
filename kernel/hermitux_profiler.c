#include "hermit/hermitux_profiler.h"

#include <hermit/logging.h>
#include <asm/irq.h>
#include <hermit/memory.h>
#include <hermit/stddef.h>
#include <asm/page.h>

#define IRQ_NUM	33 /* corresponds to irq 1 when injected from kvm */
#define PAGES_FOR_SAMPLES	256

extern uint64_t tux_prof_samples;
extern uint64_t tux_prof_samples_num;

uint64_t *samples;
uint64_t next_id;
uint64_t max_id;

static void profiler_irq_handler(struct state *s) {
	samples[next_id++] = s->rip;

	if(tux_prof_samples_num < max_id)
		tux_prof_samples_num++;

	if (next_id >= max_id) {
		LOG_WARNING("Profiler sample buffer full, wraping to 0\n");
		next_id = 0;
	}
}

int hermitux_profiler_init(void) {

	/* Allocate memory for samples */
	samples = kmalloc(PAGES_FOR_SAMPLES * PAGE_SIZE);
	if(!samples) {
		LOG_ERROR("Cannot allocate memory for profiling samples\n");
		return -1;
	}
	tux_prof_samples = (uint64_t)virt_to_phys((size_t)samples);

	next_id = 0;
	max_id = (PAGES_FOR_SAMPLES * PAGE_SIZE) / sizeof(uint64_t);

	/* install profiler irq handler */
	irq_install_handler(IRQ_NUM, profiler_irq_handler);

	return 0;
}
