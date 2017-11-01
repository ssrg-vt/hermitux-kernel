#ifndef NO_IRCCE

#include <hermit/syscall.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <hermit/memory.h>
#include <hermit/rcce.h>
#include <hermit/logging.h>

extern int32_t isle;

int sys_rcce_fini(int session_id)
{
	int i, j;
	int ret = 0;

	// we have to free the MPB

	if (is_single_kernel())
		return -ENOSYS;

	if (session_id <= 0)
		return -EINVAL;

	islelock_lock(rcce_lock);

	for(i=0; i<MAX_RCCE_SESSIONS; i++)
	{
		if (rcce_mpb[i].id == session_id)
			break;
	}

	if (i >= MAX_RCCE_SESSIONS) {
		ret = -EINVAL;
		goto out;
	}

	if (rcce_mpb[i].mpb[isle]) {
		if (is_hbmem_available())
			hbmem_put_pages(rcce_mpb[i].mpb[isle], RCCE_MPB_SIZE / PAGE_SIZE);
		else
			put_pages(rcce_mpb[i].mpb[isle], RCCE_MPB_SIZE / PAGE_SIZE);
	}
	rcce_mpb[i].mpb[isle] = 0;

	for(j=0; (j<MAX_ISLE) && !rcce_mpb[i].mpb[j]; j++) {
		PAUSE;
	}

	// rest full session
	if (j >= MAX_ISLE)
		rcce_mpb[i].id = 0;

out:
	islelock_unlock(rcce_lock);

	return ret;
}

#endif /* NO_IRCCE */
