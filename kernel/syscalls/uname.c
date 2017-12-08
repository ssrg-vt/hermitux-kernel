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
	strcpy(buf->sysname, "Linux");
	strcpy(buf->nodename, "ghost_reveries");
	strcpy(buf->release, "4.9.0-4-amd64");
	strcpy(buf->version, "#1 SMP Debian 4.9.51-1 (2017-09-28)");
	strcpy(buf->machine, "x86_64");
	strcpy(buf->domainname, "");

	return 0;
}
