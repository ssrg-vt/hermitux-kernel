#include <hermit/minifs.h>

#include <hermit/stddef.h>
#include <asm/stddef.h>
#include <asm/page.h>
#include <hermit/string.h>
#include <hermit/errno.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <asm/atomic.h>

#define DIE()	asm("int $3")

#define MAX_FILES			100000
#define MAX_FDS				100000
//#define MAX_FILE_SIZE_PG	32
#define MAX_FILE_SIZE_PG	64

#define O_RDONLY	    0000
#define O_WRONLY	    0001
#define O_CREAT			0100
#define SEEK_SET		0
#define SEEK_CUR		1
#define SEEK_END		2

typedef struct s_file {
	char *name;
	uint64_t size;
	char *pages[MAX_FILE_SIZE_PG]; //TODO this limits the max size
	int (*read)(int, void *, uint64_t); // custom read function
	int (*write)(int, const void *, uint64_t); // custom write function
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

#define MINIFS_LOAD_MAXPATH		128
typedef struct {
	char hostpath[MINIFS_LOAD_MAXPATH];
	char guestpath[MINIFS_LOAD_MAXPATH];
} __attribute__((packed)) uhyve_minifs_load_t;

/* Optimization avenue: this scales linearly with the maximum number of files */
static file *minifs_find_file(const char *pathname) {

	//LOG_INFO("minifs_find_file %s\n", pathname);

	for(int i=0; i<MAX_FILES; i++)
		if(files[i].name && !strcmp(pathname, files[i].name))
			return &(files[i]);

	return NULL;
}

/* Used to initialize minifs with existing files */
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

	/* FIXME: this is disabled for now to allow mapping the C library (which
	 * is quite large) with dynamically compiled programs. */
#if 0
	/* Check that the file is not too big */
	if(filesize > MAX_FILE_SIZE_PG*PAGE_SIZE) {
		LOG_ERROR("minifs_load_from_host: %s size is superior to the max file "
				"size (%d)", filename, MAX_FILE_SIZE_PG*PAGE_SIZE);
		goto out;
	}
#endif

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

int devnull_write(int fd, void *buf, uint64_t len) {
	return len;
}

int devnull_read(int fd, void *buf, uint64_t len) {
	return 0;
}

int devzero_write(int fd, void *buf, uint64_t len) {
	return len;
}

int devzero_read(int fd, void *buf, uint64_t len) {
	memcpy(buf, 0x0, len);
	return len;
}

/* https://www.codeproject.com/Articles/25172/Simple-Random-Number-Generation */
static uint32_t getrand(void) {
	static uint32_t m_z, m_w;

	m_z = 36969 * (m_z & 65535) + (m_z >> 16);
	m_w = 18000 * (m_w & 65535) + (m_w >> 16);
	return (m_z << 16) + m_w;
}

int devrandom_write(int fd, void *buf, uint64_t len) {
	return len;
}

int devrandom_read(int fd, void *buf, uint64_t len) {
	uint8_t ran;

	for(int i=0; i<len; i++) {
		ran = getrand();
		memcpy(buf+i, &ran, 1);
	}

	return len;
}


#define CPUINFO_SIZE_PG	2
char cpuinfo_buffer[PAGE_SIZE*CPUINFO_SIZE_PG];
extern atomic_int32_t possible_cpus;

int cpuinfo_read(int fd, void *buf, uint64_t len) {
	size_t offset = fds[fd].offset;
	uint32_t freq = get_cpu_frequency();

	cpuinfo_buffer[0] = '\0';
	for(int i=0; i<atomic_int32_read(&possible_cpus); i++) {
		ksprintf(cpuinfo_buffer, "%sprocessor:\t%d\n", cpuinfo_buffer, i);
		ksprintf(cpuinfo_buffer, "%scpu_MHz:\t%u\n", cpuinfo_buffer, freq);
	}

	if(offset > strlen(cpuinfo_buffer))
		return 0;

	if(offset + len > strlen(cpuinfo_buffer))
		len = strlen(cpuinfo_buffer)-offset;

	memcpy(buf, cpuinfo_buffer+offset, len);
	fds[fd].offset += len;
	return len;
}

int cpuinfo_write(int fd, const void *buf, uint64_t len) {
	return len;
}

#define MEMINFO_SIZE_PG	1
char meminfo_buffer[PAGE_SIZE*MEMINFO_SIZE_PG];
extern atomic_int64_t total_allocated_pages;
extern atomic_int64_t total_available_pages;

int meminfo_read(int fd, void *buf, uint64_t len) {
	size_t offset = fds[fd].offset;
	size_t total = atomic_int64_read(&total_available_pages) * PAGE_SIZE;
	size_t free = total - atomic_int64_read(&total_allocated_pages) * PAGE_SIZE;

	meminfo_buffer[0] = '\0';

	ksprintf(meminfo_buffer, "%sMemTotal:\t%d\n", meminfo_buffer, total);
	ksprintf(meminfo_buffer, "%sMemFree:\t%u\n", meminfo_buffer, free);

	if(offset > strlen(meminfo_buffer))
		return 0;

	if(offset + len > strlen(meminfo_buffer))
		len = strlen(meminfo_buffer)-offset;

	memcpy(buf, meminfo_buffer+offset, len);
	fds[fd].offset += len;
	return len;
}


int meminfo_write(int fd, const void *buf, uint64_t len) {
	return len;
}

int minifs_creat_custom(const char *pathname, mode_t mode, void *read,
		void *write);

int minifs_init(void) {
	int hostload_done = 0;

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

	/* Load files from the host if needed with help from uhyve */
	while(!hostload_done) {
		uhyve_minifs_load_t arg;
		uhyve_send(UHYVE_PORT_MINIFS_LOAD,
				(unsigned)virt_to_phys((size_t) &arg));
		if(arg.hostpath[0] != '\0')
			minifs_load_from_host(arg.hostpath, arg.guestpath);
		else
			hostload_done = 1;
	}

	/* Create pseudo files to emulate Linux interface */
	minifs_creat_custom("/dev/null", 0777, devnull_read, devnull_write);
	minifs_creat_custom("/dev/zero", 0777, devzero_read, devzero_write);
	minifs_creat_custom("/dev/random", 0777, devrandom_read, devrandom_write);
	minifs_creat_custom("/dev/urandom", 0777, devrandom_read, devrandom_write);
	minifs_creat_custom("/proc/cpuinfo", 0777, cpuinfo_read, cpuinfo_write);
	minifs_creat_custom("/proc/meminfo", 0777, meminfo_read, meminfo_write);

	return 0;
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
			files[i].read = NULL;
			files[i].write = NULL;

			for(int j=0; j<MAX_FILE_SIZE_PG; j++)
				files[i].pages[j] = 0;

			return 0;
		}
	}

	LOG_ERROR("minifs_creat: max number of files reached\n");
	DIE();
	return -ENOMEM;
}

/* Used to create pseudo fiels with custom RW functions */
int minifs_creat_custom(const char *pathname, mode_t mode, void *read,
		void *write) {
	int i = 0;

	//LOG_INFO("minifs_create_custom %s\n", pathname);

	for(i=0; i<MAX_FILES; i++) {
		if(files[i].name == NULL) {
			files[i].name = kmalloc(strlen(pathname) + 1);
			if(!files[i].name)
				return -ENOMEM;
			strcpy(files[i].name, pathname);
			files[i].size = 0;
			files[i].read = read;
			files[i].write = write;

			for(int j=0; j<MAX_FILE_SIZE_PG; j++)
				files[i].pages[j] = 0;

			return 0;
		}
	}

	LOG_ERROR("minifs_creat: max number of files reached\n");
	DIE();
	return -ENOMEM;
}
/* This does the exact same thing as minifs_create, but it does not adhere to
 * the creat interface: it returns a pointer to the created file object. This is
 * called from minifs_open when the O_CREAT flag is used, and result in a
 * optimization */
static file * minifs_internal_creat(const char *pathname, mode_t mode) {
	int i = 0;

	//LOG_INFO("minifs_internal_create %s\n", pathname);

	for(i=0; i<MAX_FILES; i++) {
		if(files[i].name == NULL) {
			files[i].name = kmalloc(strlen(pathname) + 1);
			if(!files[i].name)
				return NULL;
			strcpy(files[i].name, pathname);
			files[i].size = 0;

			for(int j=0; j<MAX_FILE_SIZE_PG; j++)
				files[i].pages[j] = 0;


			return &(files[i]);
		}
	}

	LOG_ERROR("minifs_internal_creat: max number of files reached\n");
	DIE();
	return NULL;
}

/* Optimization avenue: this scales linearly with the number of opened files */
int minifs_open(const char *pathname, int flags, mode_t mode) {
	file *f;
	//LOG_INFO("minifs_open %s\n", pathname);

	if(flags & O_CREAT) {
		f = minifs_internal_creat(pathname, mode);
		if(!f)
			return -ENOMEM;
	 } else
		 f = minifs_find_file(pathname);

	if(!f)
		return -ENOENT;

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

	if(fds[fd].f->read)
		return fds[fd].f->read(fd, buf, count);

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

int minifs_write(int fd, const void *buf, size_t count) {
	size_t cur_count;
	size_t total_bytes_to_write = count;

//	LOG_INFO("minifs_write %d for %d bytes, offset %d (cur. size %d)\n", fd, count,
//			fds[fd].offset, fds[fd].f->size);
	if(!count)
		return 0;

	/* Do we have a custom write function for this file */
	if(fds[fd].f->write)
		return fds[fd].f->write(fd, buf, count);

	/* Iterate over the file's pages concerned by the read */
	while(count) {
		uint64_t offset = fds[fd].offset;

		if(!(offset % PAGE_SIZE))
			cur_count = (count < PAGE_SIZE) ? count : PAGE_SIZE;
		else {
			cur_count = (offset + count) > PAGE_CEIL(offset) ?
				PAGE_CEIL(offset) - offset : count;
		}

		/* FIXME: this is disabled for now to allow mapping the C library (which
		 * is quite large) with dynamically compiled programs. */
#if 0
		/* Check that we don't go over the max file size */
		if(offset/PAGE_SIZE > MAX_FILE_SIZE_PG) {
			LOG_ERROR("Trying to write past the max file size (%d)\n",
					MAX_FILE_SIZE_PG*PAGE_SIZE);
			DIE();
			return total_bytes_to_write - count;
		}
#endif

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
