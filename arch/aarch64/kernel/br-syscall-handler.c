#include <asm/stddef.h>
#include <asm/br_syscall_handler.h>
#include <hermit/logging.h>
#include <hermit/errno.h>

int br_syscall_handler(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
        uint64_t x4, uint64_t x5) {
    uint64_t id;
    asm volatile ("mov %0, x8" : "=r"(id) ::);

#if 0
    LOG_INFO("br_syscall_handler id %d - x0: 0x%llx, x1: 0x%llx, x2: 0x%llx, "
            "x3: 0x%llx, x4: 0x%llx, x5: 0x%llx\n", id, x0, x1, x2, x3, x4, x5);
#endif

    switch(id) {
        case 96:
            return sys_set_tid_address((void *)x0);

        case 29:
            return sys_ioctl(x0, x1, x2);

        case 56:
            return sys_openat(x0, (void *)x1, x2, x3);

        case 57:
            return sys_close(x0);

        case 64:
            return sys_write(x0, (void *)x1, x2);

        case 66:
            return sys_writev(x0, (void *)x1, x2);

        case 94:
            sys_exit_group(x0);
            /* does not return */

        case 173:
            return sys_getppid();
    }

    LOG_ERROR("BR_SYSCALL ID %d not supported\n", id);
    return -ENOSYS;
}
