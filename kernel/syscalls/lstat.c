#include <hermit/syscall.h>

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

int sys_lstat(const char* file, struct stat *st)
{
	/* FIXME take care of the symbolic link */
	int fd, ret;
	/* 0 is O_RDONLY */
	fd = sys_open(file, 0x0, 0x0);
	ret = sys_fstat(fd, st);
	return ret;
}

