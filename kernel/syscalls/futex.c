#include <hermit/syscall.h>
#include <hermit/tasks.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>
#include <asm/atomic.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

#define FUTEX_PRIVATE_FLAG		128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

typedef struct __futex_q {
	int* futex;
	int waiters[MAX_TASKS];
	struct __futex_q* next;
	struct __futex_q* prev;
} futex_q;

static futex_q* head = NULL;

spinlock_irqsave_t futex_lock = SPINLOCK_IRQSAVE_INIT;

inline static int futex_wait(int* futex, int val) {

	int f_val = atomic_int32_read(((atomic_int32_t *)futex));
	if (f_val != val) {
		spinlock_irqsave_unlock(&futex_lock);
		return -EAGAIN;
	}

	task_t* curr_task = per_core(current_task);

	// if the futex is in the list, then add this task as a waiter to the list
	futex_q* walk = head;
	while (walk) {
		if (walk->futex == futex) {
			walk->waiters[curr_task->id] = 1;
			break;
		}

		walk = walk->next;
	}

	// walk will be null if it wasn't in the list.
	if (!walk) {
		walk = (futex_q*)kmalloc(sizeof(*walk));
		walk->futex = futex;
		for(int i=0; i<MAX_TASKS; i++)
			walk->waiters[i] = 0;
		walk->waiters[curr_task->id] = 1;

		// push front
		if (head) {
			head->prev = walk;
			walk->next = head;
			walk->prev = NULL;
			head = walk;
		} else {
			head = walk;
			walk->next = NULL;
			walk->prev = NULL;
		}
	}

	// Now that the futex and waiters are in the list, we can block
	spinlock_irqsave_unlock(&futex_lock);
	block_current_task();
	reschedule();

	return 0;
}

inline static int futex_wake(int* futex) {

	// Try to find the futex
	futex_q* walk = head;
	int id_to_wake = 0;

	while (walk) {
		if (walk->futex == futex) {
			for(int i=0; i<MAX_TASKS; i++)
				if(walk->waiters[i]) {
					id_to_wake = i;
					walk->waiters[i] = 0;
					break;
				}
			break;
		}

		walk = walk->next;
	}

	if (!id_to_wake) {
		// remove the futex and free if there was one
		if (walk) {
			if (walk == head) {
				head = walk->next;
				kfree(walk);
			} else {
				walk->prev->next = walk->next;
				if (walk->next) {
					walk->next->prev = walk->prev;
				}

				kfree(walk);
			}
		}
		// no waiters woken up
		return 0;
	}

	// Only waking up one waiter for now
	wakeup_task(id_to_wake);
	return 1;
}

int sys_futex(int *uaddr, int futex_op, int val, const struct timespec *timeout,
		int *uaddr2, int val3) {

	int cmd = futex_op & FUTEX_CMD_MASK;
	int ret;

	if(unlikely(!uaddr)) {
		LOG_ERROR("futex: uaddr is null\n");
		return -EINVAL;
	}

	if(futex_op & FUTEX_PRIVATE_FLAG)
		return -ENOSYS;

	switch(cmd) {
		case FUTEX_WAIT:
			spinlock_irqsave_lock(&futex_lock);
			ret = futex_wait(uaddr, val);
			/* wait takes care of unlock */
			return ret;

		case FUTEX_WAKE:

			if(val != 1) {
				LOG_ERROR("futex: cannot wake more than 1 thread\n");
				return -ENOSYS;
			}

			spinlock_irqsave_lock(&futex_lock);
			ret = futex_wake(uaddr);
			spinlock_irqsave_unlock(&futex_lock);
			return ret;

		default:
			LOG_ERROR("Unsupported futex operation\n");
			return -ENOSYS;
	}
	return -ENOSYS;
}

