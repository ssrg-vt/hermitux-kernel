#include <hermit/syscall.h>
#include <hermit/logging.h>

extern char hermitux_hostname[];
extern size_t hermitux_hostname_len;

struct utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

int sys_uname(struct utsname *buf) {
	if(!buf) {
		LOG_ERROR("uname: buf is null\n");
		return -EINVAL;
	}

	memset(buf , 0x0, sizeof(struct utsname));
	strcpy(buf->sysname, "HermiTux");
	strcpy(buf->nodename, hermitux_hostname);
	strcpy(buf->release, "4.9.0-4-amd64");    /* Faking Linux here for compat with glibc */
	strcpy(buf->version, "0.1-may-2018");
	strcpy(buf->machine, "x86_64");
	strcpy(buf->domainname, "");

	return 0;
}
