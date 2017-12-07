#include <hermit/syscall.h>

int sys_tgkill(int tgid, int tid, int sig) {
	return sys_kill(tid, sig);
}
