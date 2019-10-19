#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <hermit/errno.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/minifs.h>

extern int hermit_dup2(int oldfd, int newfd);

typedef struct {
    int oldfd;
    int newfd;
    int ret;
} __attribute__ ((packed)) uhyve_dup2_t;


int sys_dup2(int oldfd, int newfd)
{
    if (unlikely(newfd == oldfd))
        return newfd;

#ifndef NO_NET
    if ((oldfd & LWIP_FD_BIT) || (newfd & LWIP_FD_BIT)) {
        LOG_ERROR("dup2: sockets not supported\n");
        return -ENOSYS;
    }
#endif

    if (likely(is_uhyve())) {

        if (minifs_enabled)
            return minifs_dup2(oldfd, newfd);

        uhyve_dup2_t uhyve_args = {oldfd, newfd, -1};
        uhyve_send(UHYVE_PORT_DUP2, (unsigned)virt_to_phys((size_t)&uhyve_args));
        return uhyve_args.ret;
    }

    LOG_ERROR("dup2: not supported with qemu isle\n");
    return -ENOSYS;
}