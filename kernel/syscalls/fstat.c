#include <hermit/syscall.h>
#include <asm/uhyve.h>
#include <asm/page.h>
#include <hermit/logging.h>
#include <hermit/minifs.h>

typedef unsigned int dev_t;
typedef unsigned int ino_t;
typedef unsigned mode_t;
typedef unsigned int nlink_t;
typedef unsigned int uid_t;
typedef unsigned short gid_t;
typedef long blksize_t;
typedef long blkcnt_t;

struct stat {
	dev_t st_dev;
	ino_t st_ino;
	nlink_t st_nlink;

	mode_t st_mode;
	uid_t st_uid;
	gid_t st_gid;
	unsigned int    __pad0;
	dev_t st_rdev;
	off_t st_size;
	blksize_t st_blksize;
	blkcnt_t st_blocks;

	struct timespec st_atim;
	struct timespec st_mtim;
	struct timespec st_ctim;
	long __unused[3];
};

typedef struct {
	int fd;
	int ret;
	struct stat *st;
} __attribute__ ((packed)) uhyve_fstat_t;

int sys_fstat(int fd, struct stat *buf)
{
	if(minifs_enabled) {
		LOG_ERROR("fstat: not supported with minifs\n");
		return -ENOSYS;
	}

	if(unlikely(!buf)) {
		LOG_ERROR("fstat: called with buf argument null\n");
		return -EINVAL;
	}

	if(likely(is_uhyve())) {
		uhyve_fstat_t uhyve_args = {fd, -1,
			(struct stat *)virt_to_phys((size_t)buf)};

		uhyve_send(UHYVE_PORT_FSTAT,
				(unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.ret;
	}

	/* qemu not supported yet */
	LOG_ERROR("fstat: not supported with qemu isle\n");
	return -ENOSYS;
}

