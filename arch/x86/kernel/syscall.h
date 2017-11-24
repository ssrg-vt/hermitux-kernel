#ifndef ARCH_KERNEL_SYSCALL_H
#define ARCH_KERNEL_SYSCALL_H

#include <hermit/stddef.h>

uint64_t redirect_syscall(uint64_t rax, uint64_t rdi, uint64_t rsi, uint64_t rdx,
			  uint64_t r10, uint64_t r8, uint64_t r9, struct state *s);


#endif /* ARCH_KERNEL_SYSCALL_H */
