#ifndef MINI_FS_H
#define MINI_FS_H

#include <asm/stddef.h>

extern char minifs_enabled;

typedef unsigned int mode_t;

int minifs_init(void);
int minifs_open(const char *pathname, int flags, mode_t mode);
int minifs_creat(const char *pathname, mode_t mode);
int minifs_unlink(const char *pathname);
int minifs_close(int fd);
int minifs_read(int fd, void *buf, size_t count);
int minifs_write(int fd, const void *buf, size_t count);
uint64_t minifs_lseek(int fd, uint64_t offset, int whence);
int minifs_mkdir(const char *pathname, mode_t mode);
int minifs_rmdir(const char *pathname);

#endif /* MINI_FS_H */
