#include <hermit/errno.h>
#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <hermit/spinlock.h>
#include <hermit/minifs.h>
#include <lwip/sockets.h>

typedef struct {
	int fd;
	unsigned int cmd;
	unsigned long arg;
	int ret;
} __attribute__((packed)) uhyve_fcntl_t;

typedef struct {
        int fd;
        int ret;
} __attribute__((packed)) uhyve_close_t;

static int invalid(int fd)
{
    return 0;
}

/**
 * if running under uhyve:
 *  - use hermit_fcntl (or sys_fcntl?) to check if newfd is in use already
 *      - if so, close it with either sys_close or hermit_close
 *      - copy data from oldfd to newfd
 * else not uhyve:
 *  - check again if LwIP fd, but use lwip_close instead of hermit_close
 *  - else use lwip_write to write to libc_sd -- set up a sys_close
 * 
 * TODO:
 * - understand when to use syscall and when to use hermit/lwip interfaces
 * - understand nuances of copying file descriptors
 */

int sys_dup2(int oldfd, int newfd)
{

    if (unlikely(newfd == oldfd))
        return newfd;

    if (invalid(oldfd))
        return -EBADF;

    if (likely(is_uhyve())) {

#ifndef NO_NET
        // not sure if correct to use hermit_fcntl, maybe use sys_fcntl?
        if (newfd & LWIP_FD_BIT) {
            int open_fd = hermit_fcntl(newfd, F_GETFL, 0);
            if (open_fd >= 0) {
                int ret = hermit_close(newfd);
                if (ret < 0)
                    return -errno;
            }
            // dup it now?
        }
#endif
        uhyve_fcntl_t uhyve_fcntl = {newfd, F_GETFL, 0, -1};
        uhyve_send(UHYVE_PORT_FCNTL, (unsigned)virt_to_phys((size_t) &uhyve_fcntl));

        if (uhyve_fcntl.ret >= 0) {
            uhyve_close_t uhyve_close = {newfd, -1};
		    uhyve_send(UHYVE_PORT_CLOSE, (unsigned)virt_to_phys((size_t) &uhyve_close));
            if (uhyve_close.ret < 0) {
                return uhyve_close.ret;
            }
            // dup it now?
        }
    }

#ifndef NO_NET

    

#endif


}