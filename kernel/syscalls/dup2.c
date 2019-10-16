#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/minifs.h>

typedef struct {
    int oldfd;
    int newfd;
    int ret;
} __attribute__ ((packed)) uhyve_dup2_t;


/**
 * Currently this implementation does not support the following:
 *  - checking if oldfd is valid
 *  - minifs file descriptors
 *  - LwIP file descriptors
 */
int sys_dup2(int oldfd, int newfd)
{

    if (minifs_enabled) {
        LOG_ERROR("dup2: not supported with minifs\n");
        return -ENOSYS;
    }

    if (unlikely(newfd == oldfd))
        return newfd;

    if (likely(is_uhyve())) {
        uhyve_dup2_t uhyve_args = {oldfd, newfd, -1};
        uhyve_send(UHYVE_PORT_DUP2, (unsigned)virt_to_phys((size_t)&uhyve_args));
        return uhyve_args.ret;
    }

    LOG_ERROR("dup2: not supported with qemu isle\n");
    return -ENOSYS;
}