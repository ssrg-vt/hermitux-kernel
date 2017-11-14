#include <hermit/syscall.h>

struct utsname {
	char sysname[33];
	char nodename[33];
	char release[33];
	char version[33];
	char machine[33];
	char domainname[33];
};

int sys_uname(struct utsname *buf) {
	/* TODO */
	memset(buf , 0x0, sizeof(struct utsname));
	strcpy(buf->sysname, "hermit");

	return 0;
}
