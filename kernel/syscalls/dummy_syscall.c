#include <hermit/syscall.h>
#include <hermit/logging.h>

#define SC_ENTER_FILE "/home/danchiba/hermitux/syscall-rewriter/eval/results/sc_entered_times"
#define O_CREAT 0100
#define O_APPEND 02000

#ifdef MEASURE_SYSCALL_ENTRY
inline static unsigned long long rdtsc(void)
{
	unsigned long lo, hi;
	asm volatile("rdtsc"
		     : "=a"(lo), "=d"(hi)::"memory");
	return ((unsigned long long)hi << 32ULL | (unsigned long long)lo);
}
#endif


int sys_dummy_syscall(void)
{
#ifdef MEASURE_SYSCALL_ENTRY
	unsigned long long entered = rdtsc();
	char buf[20];
	ksprintf(buf, "%llu\n", entered);
	int sc_res_file = sys_open(SC_ENTER_FILE, O_CREAT | O_APPEND, 00400 | 00200);
	//LOG_INFO("DC: In sys_ioctl(): sc_res_file = %d\n", sc_res_file);
	/* LOG_INFO("DC: In sys_ioctl(): buf = %s\n", buf); */
	sys_write(7, buf, strlen(buf));
	sys_close(sc_res_file);
#endif
	//LOG_INFO("In the dummy syscall\n"); 
	return 2468;
}
