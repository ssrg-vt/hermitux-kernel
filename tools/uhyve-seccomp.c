#include "uhyve-seccomp.h"

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

#define DENY_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(call), 0) < 0) goto out; }
#define ALLOW_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 0) < 0) goto out; }

extern int kvm, vmfd, *vcpu_fds;

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

int setup_ioctl_rules(scmp_filter_ctx *ctx) {
	int ret;

	/* Allow IOCTL */
	ret = seccomp_rule_add(*ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
	if(ret < 0)
		return -1;

	/* TODO filter based on:
	 * - Files (only allow /dev/kvm, vmfd, vcpufds
	 * - Operations made on each file
	 */

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

	/* Allow READ */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	if(ret < 0)
		goto out;

	/* Allow WRITE */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	if(ret < 0)
		goto out;

	ALLOW_RULE(close);
	ALLOW_RULE(exit_group);
	ALLOW_RULE(openat);
	ALLOW_RULE(access);
	ALLOW_RULE(fstat);
	ALLOW_RULE(lseek);
	ALLOW_RULE(mkdir);
	ALLOW_RULE(rmdir);
	ALLOW_RULE(unlink);
	ALLOW_RULE(getcwd);

	if(setup_ioctl_rules(&ctx))
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
