#ifndef NO_IRCCE

#include <hermit/syscall.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <hermit/memory.h>
#include <hermit/rcce.h>
#include <hermit/logging.h>
#include <hermit/vma.h>

extern int32_t isle;

size_t sys_rcce_malloc(int session_id, int ue)
{
	size_t vaddr = 0;
	int i, counter = 0;

	if (is_single_kernel())
		return -ENOSYS;

	if (session_id <= 0)
		return -EINVAL;

	// after 120 retries (= 120*300 ms) we give up
	do {
		for(i=0; i<MAX_RCCE_SESSIONS; i++)
		{
			if ((rcce_mpb[i].id == session_id) && rcce_mpb[i].mpb[ue])
				break;
		}

		if (i >= MAX_RCCE_SESSIONS) {
			counter++;
			timer_wait((300*TIMER_FREQ)/1000);
		}
	} while((i >= MAX_RCCE_SESSIONS) && (counter < 120));

	LOG_DEBUG("i = %d, counter = %d, max %d\n", i, counter, MAX_RCCE_SESSIONS);

	// create new session
	if (i >= MAX_RCCE_SESSIONS)
		goto out;

	vaddr = vma_alloc(RCCE_MPB_SIZE, VMA_READ|VMA_WRITE|VMA_USER|VMA_CACHEABLE);
        if (BUILTIN_EXPECT(!vaddr, 0))
		goto out;

	if (page_map(vaddr, rcce_mpb[i].mpb[ue], RCCE_MPB_SIZE / PAGE_SIZE, PG_RW|PG_USER|PG_PRESENT)) {
		vma_free(vaddr, vaddr + 2*PAGE_SIZE);
		goto out;
	}

	LOG_INFO("Map MPB of session %d at 0x%zx, using of slot %d, isle %d\n", session_id, vaddr, i, ue);

	if (isle == ue)
		memset((void*)vaddr, 0x0, RCCE_MPB_SIZE);

	return vaddr;

out:
	LOG_ERROR("Didn't find a valid MPB for session %d, isle %d\n", session_id, ue);

	return 0;
}

#endif /* NO_IRCCE */
