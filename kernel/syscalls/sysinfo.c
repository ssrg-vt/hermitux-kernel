#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <asm/atomic.h>

struct sysinfo {
   long uptime;             /* Seconds since boot */
   unsigned long loads[3];  /* 1, 5, and 15 minute load averages */
   unsigned long totalram;  /* Total usable main memory size */
   unsigned long freeram;   /* Available memory size */
   unsigned long sharedram; /* Amount of shared memory */
   unsigned long bufferram; /* Memory used by buffers */
   unsigned long totalswap; /* Total swap space size */
   unsigned long freeswap;  /* Swap space still available */
   unsigned short procs;    /* Number of current processes */
   unsigned long totalhigh; /* Total high memory size */
   unsigned long freehigh;  /* Available high memory size */
   unsigned int mem_unit;   /* Memory unit size in bytes */
   char _f[20-2*sizeof(long)-sizeof(int)];
							/* Padding to 64 bytes */
};

extern atomic_int64_t total_pages;
extern atomic_int64_t total_available_pages;

int sys_sysinfo(struct sysinfo *info) {

	if(unlikely(!info)) {
		LOG_ERROR("sysinfo: info is null\n");
		return -EINVAL;
	}

	/* uptime */
	info->uptime = get_clock_tick() / TIMER_FREQ;

	/* LOAD TODO */
	info->loads[0] = 0;
	info->loads[1] = 0;
	info->loads[3] = 0;

	/* RAM */
	info->totalram = atomic_int64_read(&total_pages) * PAGE_SIZE;
	info->freeram = atomic_int64_read(&total_available_pages) * PAGE_SIZE;
	info->sharedram = 0;
	info->bufferram = 0;

	/* swap */
	info->totalswap = 0;
	info->freeswap = 0;

	/* processes: just 1, we are in a unikernel */
	info->procs = 1;

	/* High memory */
	info->totalhigh = 0;
	info->freehigh = 0;

	/* units */
	info->mem_unit = 1;

	return 0;
}
