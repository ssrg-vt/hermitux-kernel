#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/page.h>

typedef unsigned int dev_t;
typedef unsigned int ino_t;
typedef unsigned short mode_t;
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

typedef struct {
	const char* name;
	int flags;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_open_t;

typedef struct {
        int fd;
        int ret;
} __attribute__((packed)) uhyve_close_t;


int sys_stat(const char* file, struct stat *st)
{
	int fd, ret;

	if(unlikely(!file || !st)) {
		LOG_ERROR("stat: file or/and st is null\n");
		return -EINVAL;
	}

	if(unlikely(!is_uhyve())) {
		LOG_ERROR("lstat: not supported with qemu isle\n");
		return -EINVAL;
	}

	/* perform open, 0x0 is O_RDONLY */
	uhyve_open_t args_o = {(const char *)virt_to_phys((size_t)file), 0x0, 0x0};
	uhyve_send(UHYVE_PORT_OPEN, (unsigned)virt_to_phys((size_t)&args_o));
	if(args_o.ret == -1) {
		LOG_ERROR("fstat: cannot open file\n");
		return -EINVAL; /* not sure if correct thing to return here ... */
	}
	fd = args_o.ret;

	/* perform fstat */
	uhyve_fstat_t args_f = {fd, -1, (struct stat *)virt_to_phys((size_t)st)};
	uhyve_send(UHYVE_PORT_FSTAT, (unsigned)virt_to_phys((size_t)&args_f));
	ret = args_f.ret;

	/* perform close */
	uhyve_close_t args_c = {fd, -1};
	uhyve_send(UHYVE_PORT_CLOSE, (unsigned)virt_to_phys((size_t)&args_c));

	return ret;
}

