#include "uhyve-seccomp.h"

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

void sigsys_handler(int signum, siginfo_t *siginfo, void *context) {
	char buf[256];
	sprintf(buf, "Syscall failed: %d\n", siginfo->si_syscall);
	syscall(1, 1, buf, strlen(buf));
	return;
}

int sigsys_handler_install(void) {
	struct sigaction sa;
 	
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &sigsys_handler;

	if(sigaction(SIGSYS, &sa, NULL) == -1) {
		fprintf(stderr, "Error installing sygsys handler\n");
		return -1;
	}

	return 0;
}

int uhyve_seccomp_init(void) {
	scmp_filter_ctx ctx;
	int ret;

	if(sigsys_handler_install())
		return -1;

	/* replace the parameter here with SCMP_ACT_KILL for full security */
	ctx = seccomp_init(SCMP_ACT_TRAP);
	if(ctx == NULL) {
		fprintf(stderr, "cannot init seccomp\n");
		return -1;
	}

	/* Allow CLOSE	*/
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	if(ret < 0)
		goto out;

	/* Allow READ */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	if(ret < 0)
		goto out;

	/* Allow WRITE */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	if(ret < 0)
		goto out;

	/* Allow EXIT_GROUP */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	if(ret < 0)
		goto out;

	/* Allow IOCTL */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
	if(ret < 0)
		goto out;

	/* Allow OPENAT */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	if(ret < 0)
		goto out;

	/* Allow ACCESS */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
	if(ret < 0)
		goto out;

	/* Allow FSTAT */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	if(ret < 0)
		goto out;

	/* Allow lseek */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
	if(ret < 0)
		goto out;

	/* Allow mkdir */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
	if(ret < 0)
		goto out;

	/* Allow rmdir */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rmdir), 0);
	if(ret < 0)
		goto out;

	/* Allow unlink */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
	if(ret < 0)
		goto out;

	/* Allow getcwd */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
	if(ret < 0)
		goto out;

	ret = seccomp_load(ctx);
	if(ret < 0) {
		fprintf(stderr, "Error loading seccomp rules\n");
		return -1;
	}

	seccomp_release(ctx);
	return 0;

out:
	fprintf(stderr, "Error adding rule to seccomp filter\n");
	seccomp_release(ctx);
	return -1;
}
