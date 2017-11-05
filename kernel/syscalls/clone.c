#include <hermit/syscall.h>
#include <hermit/tasks.h>
#include <hermit/spinlock.h>
#include <hermit/logging.h>
#include <hermit/time.h>

extern task_t *task_table;
extern spinlock_irqsave_t table_lock;
extern readyqueues_t *readyqueues;

int clone_task(tid_t* id, entry_point_t ep, void* arg, uint8_t prio);

int sys_clone(tid_t* id, void* ep, void* argv)
{
	return clone_task(id, ep, argv, per_core(current_task)->prio);
}

int clone_task(tid_t* id, entry_point_t ep, void* arg, uint8_t prio)
{
	int ret = -EINVAL;
	uint32_t i;
	void* stack = NULL;
	void* ist = NULL;
	task_t* curr_task;
	uint32_t core_id;

	if (BUILTIN_EXPECT(!ep, 0))
		return -EINVAL;
	if (BUILTIN_EXPECT(prio == IDLE_PRIO, 0))
		return -EINVAL;
	if (BUILTIN_EXPECT(prio > MAX_PRIO, 0))
		return -EINVAL;

	curr_task = per_core(current_task);

	stack = create_stack(DEFAULT_STACK_SIZE);
	if (BUILTIN_EXPECT(!stack, 0))
		return -ENOMEM;

	ist =  create_stack(KERNEL_STACK_SIZE);
	if (BUILTIN_EXPECT(!ist, 0)) {
		destroy_stack(stack, DEFAULT_STACK_SIZE);
		return -ENOMEM;
	}

	spinlock_irqsave_lock(&table_lock);

	core_id = get_next_core_id();
	if (BUILTIN_EXPECT(core_id >= MAX_CORES, 0))
	{
		spinlock_irqsave_unlock(&table_lock);
		ret = -EINVAL;
		goto out;
	}

	for(i=0; i<MAX_TASKS; i++) {
		if (task_table[i].status == TASK_INVALID) {
			task_table[i].id = i;
			task_table[i].status = TASK_READY;
			task_table[i].last_core = core_id;
			task_table[i].last_stack_pointer = NULL;
			task_table[i].stack = stack;
			task_table[i].prio = prio;
			task_table[i].heap = curr_task->heap;
			task_table[i].start_tick = get_clock_tick();
			task_table[i].last_tsc = 0;
			task_table[i].parent = curr_task->id;
			task_table[i].tls_addr = curr_task->tls_addr;
			task_table[i].tls_size = curr_task->tls_size;
			task_table[i].ist_addr = ist;
			task_table[i].lwip_err = 0;
			task_table[i].signal_handler = NULL;

			if (id)
				*id = i;

			ret = create_default_frame(task_table+i, ep, arg, core_id);
			if (ret)
				goto out;

                        // add task in the readyqueues
			spinlock_irqsave_lock(&readyqueues[core_id].lock);
			readyqueues[core_id].prio_bitmap |= (1 << prio);
			readyqueues[core_id].nr_tasks++;
			if (!readyqueues[core_id].queue[prio-1].first) {
				task_table[i].next = task_table[i].prev = NULL;
				readyqueues[core_id].queue[prio-1].first = task_table+i;
				readyqueues[core_id].queue[prio-1].last = task_table+i;
			} else {
				task_table[i].prev = readyqueues[core_id].queue[prio-1].last;
				task_table[i].next = NULL;
				readyqueues[core_id].queue[prio-1].last->next = task_table+i;
				readyqueues[core_id].queue[prio-1].last = task_table+i;
			}
			// should we wakeup the core?
			if (readyqueues[core_id].nr_tasks == 1)
				wakeup_core(core_id);
			spinlock_irqsave_unlock(&readyqueues[core_id].lock);
 			break;
		}
	}

	spinlock_irqsave_unlock(&table_lock);

	if (!ret) {
		LOG_DEBUG("start new thread %d on core %d with stack address %p\n", i, core_id, stack);
	}

out:
	if (ret) {
		destroy_stack(stack, DEFAULT_STACK_SIZE);
		destroy_stack(ist, KERNEL_STACK_SIZE);
	}

	return ret;
}

