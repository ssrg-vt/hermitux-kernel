#include <hermit/minifs.h>

#include <hermit/stddef.h>
#include <asm/stddef.h>
#include <asm/page.h>
#include <hermit/string.h>
#include <hermit/errno.h>
#include <hermit/logging.h>

#define MAX_FILES		10000
#define MAX_FDS			1000

#define O_CREAT			0100
#define SEEK_SET		0
#define SEEK_CUR		1

typedef struct s_file {
	char *name;
	uint64_t size;
	char *data;
	uint8_t is_directory;
} file;

typedef struct s_fd {
	file *f;
	uint64_t offset;
} fd;

file *files = NULL;
fd *fds = NULL;

int minifs_init(void) {
	files = kmalloc(MAX_FILES * sizeof(file));
	if(!files)
		return -ENOMEM;

	for(int i=0; i<MAX_FILES; i++)
		files[i].name = NULL;

	fds = kmalloc(MAX_FDS * sizeof(fd));
	if(!fds)
		return -ENOMEM;

	for(int i=0; i<MAX_FDS; i++)
		fds[i].f = NULL;

	return 0;
}

/* Optimization avenue: this scales linearly with the maximum number of files */
static file *minifs_find_file(const char *pathname) {

	LOG_INFO("minifs_find_file %s\n", pathname);

	for(int i=0; i<MAX_FILES; i++) {
		if(files[i].name && !strcmp(pathname, files[i].name))
			return &(files[i]);
	}
	return NULL;
}

int mkdir(const char *pathname, mode_t mode) {
	return -ENOSYS;
}

int rmdir(const char *pathname) {
	return -ENOSYS;
}

/* Optimization avenue: this scales linearly with the number of opened files */
int minifs_open(const char *pathname, int flags, mode_t mode) {
	LOG_INFO("minifs_open %s\n", pathname);

	file *f = minifs_find_file(pathname);

	if(f && f->is_directory) {
		LOG_ERROR("minifs_open: cannot open a directory\n");
		return -EINVAL;
	}

	if(!f) {
		if(flags & O_CREAT) {
			if(minifs_creat(pathname, mode))
				return -ENOMEM;
			f = minifs_find_file(pathname);
		} else
			return -EINVAL;
	}

	/* Create a file descriptor (dont use fds 0/1/2 as they are stdout, etc.) */
	for(int i=3; i<MAX_FDS; i++)
		if(fds[i].f == NULL) {
			fds[i].f = f;
			fds[i].offset = 0;
			LOG_INFO(" minifs_open returns fd %d\n", i);
			return i;
		}

	LOG_ERROR("minifs_open: max number of fds reached\n");
	return -ENOMEM;
}

/* Optimization avenue: this scales linearly with the number of existing
 * files */
int minifs_creat(const char *pathname, mode_t mode) {
	int i = 0;

	LOG_INFO("minifs_create %s\n", pathname);

	for(i=0; i<MAX_FILES; i++) {
		if(files[i].name == NULL) {
			files[i].name = kmalloc(strlen(pathname + 1));
			strcpy(files[i].name, pathname);
			files[i].size = 0;
			files[i].is_directory = 0;
			return 0;
		}
	}

	LOG_ERROR("minifs_creat: max number of files reached\n");
	return -ENOMEM;
}

int minifs_unlink(const char *pathname) {

	LOG_INFO("minifs_unlink %s\n");

	file *f = minifs_find_file(pathname);
	if(f) {
		kfree(f->name);
		kfree(f->data);
		f->name = NULL;
	} else {
		LOG_ERROR("minifs_unlink: cannot find file %s\n", pathname);
		return -ENOENT;
	}

	return 0;
}

int minifs_close(int fd) {
	fds[fd].f = NULL;
	fds[fd].offset = 0;
	return 0;
}

int minifs_read(int fd, void *buf, size_t count) {
	LOG_INFO("minifs_read %d for %d bytes (offset %d)\n", fd, count,
			fds[fd].offset);

	memcpy(buf, fds[fd].f->data + fds[fd].offset, count);
	fds[fd].offset += count;
	return count;
}

/* Optimization avenue: if this modifies the size of the file, we are currently
 * doing a full copy of the old content of the file */
int minifs_write(int fd, const void *buf, size_t count) {
	file *f = fds[fd].f;

	LOG_INFO("minifs_write %d for %d bytes: %s (offset %d)\n", fd, count, buf,
			fds[fd].offset);

	uint64_t new_size = fds[fd].offset + count;
	if(f->size < new_size) {
		/* need to increase the size of this file */
		char *data = kmalloc(new_size);
		memcpy(data, f->data, f->size);
		kfree(f->data);
		f->data = data;
	}

	/* Perform the write */
	memcpy(f->data + fds[fd].offset, buf, count);
	fds[fd].offset += count;

	return count;
}

uint64_t minifs_lseek(int fd, uint64_t offset, int whence) {

	LOG_INFO("minifs_lseek fd %d, offset %d, whence %d\n", fd, offset, whence);

	switch(whence) {
		case SEEK_SET:
			fds[fd].offset = offset;
			return offset;
		case SEEK_CUR:
			fds[fd].offset += offset;
			return fds[fd].offset;
		default:
			break;
	}

	LOG_ERROR("minifs_lseek: unsupported whence %d\n", whence);
	return -ENOSYS;
}
