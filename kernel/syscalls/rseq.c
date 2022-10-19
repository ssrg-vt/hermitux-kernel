#include <hermit/syscall.h>
#include <hermit/logging.h>

int sys_rseq(void *rseq, uint32_t rseq_len, int flags, uint32_t sig ) {
	LOG_WARNING("syscall rseq (334) unsupported, faking\n");	
	return 0;
}

