#include <hermit/minifs.h>

#include <hermit/stddef.h>
#include <asm/stddef.h>
#include <asm/page.h>
#include <hermit/string.h>
#include <hermit/errno.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>

#define DIE()	asm("int $3")

#define MAX_FILES			100000
#define MAX_FDS				100000
#define MAX_FILE_SIZE_PG	32

#define O_RDONLY	    0000
#define O_WRONLY	    0001
#define O_CREAT			0100
#define SEEK_SET		0
#define SEEK_CUR		1
#define SEEK_END		2

typedef struct s_file {
	char *name;
	uint64_t size;
	char *pages[MAX_FILE_SIZE_PG]; //TODO this limits the max size to 64 * 4KB
} file;

typedef struct s_fd {
	file *f;
	uint64_t offset;
} fd;

static file *files = NULL;
static fd *fds = NULL;

typedef struct {
	const char* name;
	int flags;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_open_t;

typedef struct {
	int fd;
	char* buf;
	size_t len;
	ssize_t ret;
} __attribute__((packed)) uhyve_read_t;

typedef struct {
	int fd;
	off_t offset;
	int whence;
} __attribute__((packed)) uhyve_lseek_t;

typedef struct {
        int fd;
        int ret;
} __attribute__((packed)) uhyve_close_t;

static void minifs_dump_file(file *f) {
	LOG_INFO("minifs_dump_file %p\n", *f);
	LOG_INFO("- name: %s\n", f->name);
	LOG_INFO("- size: %d\n", f->size);
	LOG_INFO(" - allocated pages:\n");
	for(int i=0; i<MAX_FILE_SIZE_PG; i++)
		if(f->pages[i])
			LOG_INFO("  - [%d]: %p (%s)\n", i, f->pages[i], f->pages[i]);
}


/* Optimization avenue: this scales linearly with the maximum number of files */
static inline file *minifs_find_file(const char *pathname) {

	//LOG_INFO("minifs_find_file %s\n", pathname);

	for(int i=0; i<MAX_FILES; i++)
		if(files[i].name && !strcmp(pathname, files[i].name))
			return &(files[i]);

	return NULL;
}

/* Used to initialize minifs with existing files */
/* TODO edit this to reflect the per-page data */
int minifs_load_from_host(const char *filename, const char *dest) {
	int fd, guest_fd, ret = -1;
	char *buffer;
	size_t filesize;
	uhyve_open_t arg_open = {(const char *)virt_to_phys((size_t)filename),
		O_RDONLY, 0, -1};
	uhyve_close_t arg_close = {0, -1};

	/* First open the file */
	uhyve_send(UHYVE_PORT_OPEN, (unsigned)virt_to_phys((size_t) &arg_open));
	fd = arg_open.ret;
	if(fd == -1) {
		LOG_ERROR("minifs_load_from_host: cannot open %s\n", filename);
		return -1;
	}

	/* Get the size with lseek */
	uhyve_lseek_t arg_lseek = {fd, 0x0, SEEK_END};
	uhyve_send(UHYVE_PORT_LSEEK, (unsigned)virt_to_phys((size_t) &arg_lseek));
	filesize = arg_lseek.offset;
	if(filesize == -1) {
		LOG_ERROR("minifs_load_from_host: cannot lseek %s\n", filename);
		goto out;
	}

	/* CHeck that the file is not too big */
	if(filesize > MAX_FILE_SIZE_PG*PAGE_SIZE) {
		LOG_ERROR("minifs_load_from_host: %s size is superior to the max file "
				"size (%d)", filename, MAX_FILE_SIZE_PG*PAGE_SIZE);
		goto out;
	}

	/* Reset file offset */
	arg_lseek.offset = 0;
	arg_lseek.whence = SEEK_SET;
	uhyve_send(UHYVE_PORT_LSEEK, (unsigned)virt_to_phys((size_t) &arg_lseek));

	buffer = kmalloc(filesize);
	if(filesize && !buffer) {
		LOG_ERROR("minifs_load_from_host: cannot allocate memory\n");
		goto out;
	}

	/* Perform read */
	uhyve_read_t arg_read = {fd, (char *)virt_to_phys((size_t)buffer), filesize, -1};
	uhyve_send(UHYVE_PORT_READ, (unsigned)virt_to_phys((size_t) &arg_read));
	if(arg_read.ret != filesize) {
		LOG_ERROR("minifs_load_from_host: error reading %s\n", filesize);
		kfree(buffer);
		goto out;
	}

	/* Create file on the guest and initialize it */
	guest_fd = minifs_open(dest, O_WRONLY | O_CREAT, 0x777);
	if(guest_fd == -1) {
		LOG_ERROR("minifs_load_from_host: cannot open guest file %s\n", dest);
		kfree(buffer);
		goto out;
	}

	/* Write the file */
	if(minifs_write(guest_fd, buffer, filesize) != filesize) {
		LOG_ERROR("minifs_load_from_host: error while writing %s\n", filename);
		goto out_close_guest;
	}

	ret = 0;

out_close_guest:
	minifs_close(guest_fd);

out:
	/* Close the host file */
	arg_close.fd = fd;
	uhyve_send(UHYVE_PORT_CLOSE, (unsigned)virt_to_phys((size_t) &arg_close));
	return ret;
}

int minifs_init(void) {

	LOG_INFO("Init minifs with support for %lld files and %lld fds\n",
			MAX_FILES, MAX_FDS);

	/* FIXME: we need chained lists here for files and fds */

	files = kmalloc(MAX_FILES * sizeof(file));
	if(!files)
		return -ENOMEM;

	for(int i=0; i<MAX_FILES; i++) {
		files[i].name = NULL;
		/* pages pointers will be zeroed at creat time */
	}

	fds = kmalloc(MAX_FDS * sizeof(fd));
	if(!fds)
		return -ENOMEM;

	for(int i=0; i<MAX_FDS; i++)
		fds[i].f = NULL;

	/* FIXME this is spcific to postmark, make a correct interface to specify
	 * which files to export */
	minifs_load_from_host(".pmrc", ".pmrc");

	return 0;
}

/* Optimization avenue: this scales linearly with the number of opened files */
int minifs_open(const char *pathname, int flags, mode_t mode) {

	//LOG_INFO("minifs_open %s\n", pathname);

	file *f = minifs_find_file(pathname);

	if(!f) {
		if(flags & O_CREAT) {
			if(minifs_creat(pathname, mode))
				return -ENOMEM;
			f = minifs_find_file(pathname);
			if(!f) {
				LOG_ERROR("Cannot find file %s after its creation\n", pathname);
				DIE();
			}
		} else
			return -ENOENT;
	}

	/* Create a file descriptor (dont use fds 0/1/2 as they are stdout, etc.) */
	for(int i=3; i<MAX_FDS; i++)
		if(fds[i].f == NULL) {
			fds[i].f = f;
			fds[i].offset = 0;
			return i;
		}

	LOG_ERROR("minifs_open: max number of fds reached\n");
	DIE();
	return -ENOMEM;
}

/* Optimization avenue: this scales linearly with the number of existing
 * files */
int minifs_creat(const char *pathname, mode_t mode) {
	int i = 0;

	//LOG_INFO("minifs_create %s\n", pathname);

	for(i=0; i<MAX_FILES; i++) {
		if(files[i].name == NULL) {
			files[i].name = kmalloc(strlen(pathname) + 1);
			if(!files[i].name)
				return -ENOMEM;
			strcpy(files[i].name, pathname);
			files[i].size = 0;

			for(int j=0; j<MAX_FILE_SIZE_PG; j++)
				files[i].pages[j] = 0;

			return 0;
		}
	}

	LOG_ERROR("minifs_creat: max number of files reached\n");
	DIE();
	return -ENOMEM;
}

int minifs_unlink(const char *pathname) {

//	LOG_INFO("minifs_unlink %s\n", pathname);

	file *f = minifs_find_file(pathname);
	if(f) {
		/* Release each of the file data pages */
		for(int i=0; i<MAX_FILE_SIZE_PG; i++)
			if(f->pages[i]) {
				kfree(f->pages[i]);
				f->pages[i] = 0;
			}

		kfree(f->name);
		f->name = NULL;
		f->pages[0] = 0;

	} else {
		LOG_ERROR("minifs_unlink: cannot find file %s\n", pathname);
		return -ENOENT;
	}

	return 0;
}

int minifs_close(int fd) {

	//LOG_INFO("minifs close fd %d (file '%s')\n", fd, fds[fd].f->name);

	fds[fd].f = NULL;
	fds[fd].offset = 0;

	return 0;
}

int minifs_read(int fd, void *buf, size_t count) {
	size_t cur_count;
	size_t total_bytes_to_read = count;
//	LOG_INFO("minifs_read %d for %d bytes (offset %d)\n", fd, count,
//			fds[fd].offset);

//	minifs_dump_file(fds[fd].f);

	/* Don't read past the end of the file */
	if(fds[fd].offset + count > fds[fd].f->size)
		count = fds[fd].f->size - fds[fd].offset;

	/* Iterate of each of the file's pages concerned by the read */
	while(count) {
		uint64_t offset = fds[fd].offset;

		if(!(offset % PAGE_SIZE))
			cur_count = (count < PAGE_SIZE) ? count : PAGE_SIZE;
		else {
			cur_count = (offset + count) > PAGE_CEIL(offset) ?
				PAGE_CEIL(offset) - offset : count;
		}

		/* Check that we don't go over the max file size */
		if(offset/PAGE_SIZE > MAX_FILE_SIZE_PG) {
			LOG_ERROR("Trying to read past the max file size\n");
			return total_bytes_to_read - count;
		}

		/* Check that the page is allocated */
		if(!fds[fd].f->pages[offset/PAGE_SIZE]) {
			LOG_ERROR("Trying to read a non existant page %d of file %s\n",
				offset/PAGE_SIZE, fds[fd].f->name);
			return total_bytes_to_read - count;
		}

		/* Perform the read */
		memcpy(buf, fds[fd].f->pages[offset/PAGE_SIZE] + offset%PAGE_SIZE,
				cur_count);

		// Update buf, count and offset
		buf += cur_count;
		count -= cur_count;
		fds[fd].offset += cur_count;
	}

	return total_bytes_to_read - count;
}

/* FIXME: This is actually the main bottleneck (in postmark at least): 80% of
 * the benchmark time is spent in here. On the other end the overhead of
 * find_file is negligible
 * Optimization avenue: if this modifies the size of the file, we are currently
 * doing a full copy of the old content of the file
 * */
int minifs_write(int fd, const void *buf, size_t count) {
	size_t cur_count;
	size_t total_bytes_to_write = count;

	if(!count)
		return 0;

//	LOG_INFO("minifs_write %d for %d bytes, offset %d (cur. size %d)\n", fd, count,
//			fds[fd].offset, fds[fd].f->size);

	/* Iterate over the file's pages concerned by the read */
	while(count) {
		uint64_t offset = fds[fd].offset;

		if(!(offset % PAGE_SIZE))
			cur_count = (count < PAGE_SIZE) ? count : PAGE_SIZE;
		else {
			cur_count = (offset + count) > PAGE_CEIL(offset) ?
				PAGE_CEIL(offset) - offset : count;
		}

		/* Check that we don't go over the max file size */
		if(offset/PAGE_SIZE > MAX_FILE_SIZE_PG) {
			LOG_ERROR("Trying to write past the max file size (%d)\n",
					MAX_FILE_SIZE_PG*PAGE_SIZE);
			DIE();
			return total_bytes_to_write - count;
		}

		/* Allocate if the page does not exist */
		if(!fds[fd].f->pages[offset/PAGE_SIZE])
			fds[fd].f->pages[offset/PAGE_SIZE] = kmalloc(PAGE_SIZE);

		/* Perform the write */
		memcpy(fds[fd].f->pages[offset/PAGE_SIZE] +	offset%PAGE_SIZE,
				buf, cur_count);

		/* Update buf, offset, count and the file size */
		buf += cur_count;
		count -= cur_count;
		fds[fd].offset += cur_count;
		if(fds[fd].f->size < fds[fd].offset)
			fds[fd].f->size = fds[fd].offset;
	}

	return total_bytes_to_write - count;
}

uint64_t minifs_lseek(int fd, uint64_t offset, int whence) {

//	LOG_INFO("minifs_lseek fd %d, offset %d, whence %d\n", fd, offset, whence);

	switch(whence) {
		case SEEK_SET:
			fds[fd].offset = offset;
			break;

		case SEEK_CUR:
			fds[fd].offset += offset;
			break;

		case SEEK_END:
			fds[fd].offset = fds[fd].f->size;
			break;

		default:
			LOG_ERROR("minifs_lseek: unsupported whence %d\n", whence);
			return -ENOSYS;
	}

	return fds[fd].offset;
}

int minifs_mkdir(const char *pathname, mode_t mode) {
	/* TODO */
	return -ENOSYS;
}

int minifs_rmdir(const char *pathname) {
	/* TODO */
	return -ENOSYS;
}
