#include <hermit/syscall.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <hermit/memory.h>
#include <hermit/rcce.h>
#include <hermit/logging.h>

extern int32_t isle;

int sys_rcce_init(int session_id)
{
	int i, err = 0;
	size_t paddr = 0;

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

	// create new session
	if (i >=MAX_RCCE_SESSIONS)
	{
		for(i=0; i<MAX_RCCE_SESSIONS; i++)
		{
			if (rcce_mpb[i].id == 0) {
				rcce_mpb[i].id = session_id;
				break;
			}
		}
	}

	if (i >= MAX_RCCE_SESSIONS)
	{
		err = -EINVAL;
		goto out;
	}

	if (is_hbmem_available())
		paddr = hbmem_get_pages(RCCE_MPB_SIZE / PAGE_SIZE);
	else
		paddr = get_pages(RCCE_MPB_SIZE / PAGE_SIZE);
	if (BUILTIN_EXPECT(!paddr, 0))
	{
		err = -ENOMEM;
		goto out;
	}

	rcce_mpb[i].mpb[isle] = paddr;

out:
	islelock_unlock(rcce_lock);

	LOG_INFO("Create MPB for session %d at 0x%zx, using of slot %d\n", session_id, paddr, i);

	return err;
}

