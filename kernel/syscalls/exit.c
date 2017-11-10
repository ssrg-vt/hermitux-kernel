#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>
#include <hermit/tasks.h>

extern spinlock_irqsave_t lwip_lock;
extern volatile int libc_sd;

void NORETURN do_sys_exit(int arg);

extern readyqueues_t *readyqueues;

#ifndef NO_NET

typedef struct {
	int sysnr;
	int arg;
} __attribute__((packed)) sys_exit_t;

#endif /* NO_NET */

/** @brief To be called by the systemcall to exit tasks */
void NORETURN sys_exit(int arg)
{
	if (is_uhyve()) {
		uhyve_send(UHYVE_PORT_EXIT, (unsigned) virt_to_phys((size_t) &arg));
	} 
#ifndef NO_NET
	else {
		sys_exit_t sysargs = {__NR_exit, arg};

		spinlock_irqsave_lock(&lwip_lock);
		if (libc_sd >= 0)
		{
			int s = libc_sd;

			lwip_write(s, &sysargs, sizeof(sysargs));
			libc_sd = -1;

			spinlock_irqsave_unlock(&lwip_lock);

			// switch to LwIP thread
			reschedule();

			lwip_close(s);
		} else {
			spinlock_irqsave_unlock(&lwip_lock);
		}
	}
#endif /* NO_NET */

	do_sys_exit(arg);
}

void NORETURN do_sys_exit(int arg)
{
	task_t* curr_task = per_core(current_task);
	void* tls_addr = NULL;
	const uint32_t core_id = CORE_ID;

	LOG_INFO("Terminate task: %u, return value %d\n", curr_task->id, arg);

	uint8_t flags = irq_nested_disable();

	// decrease the number of active tasks
	spinlock_irqsave_lock(&readyqueues[core_id].lock);
	readyqueues[core_id].nr_tasks--;
	spinlock_irqsave_unlock(&readyqueues[core_id].lock);

	// do we need to release the TLS?
	tls_addr = (void*)get_tls();
	if (tls_addr) {
		LOG_INFO("Release TLS at %p\n", (char*)tls_addr - curr_task->tls_size);
		kfree((char*)tls_addr - curr_task->tls_size - TLS_OFFSET);
	}

	curr_task->status = TASK_FINISHED;
	reschedule();

	irq_nested_enable(flags);

	LOG_ERROR("Kernel panic: scheduler found no valid task\n");
	while(1) {
		HALT;
	}
}

