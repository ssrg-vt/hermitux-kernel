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

scmp_filter_ctx ctx;

void sigsys_handler(int signum, siginfo_t *siginfo, void *context) {
	char buf[256];
	sprintf(buf, "Syscall failed: %d\n", siginfo->si_syscall);
	syscall(1, 1, buf, strlen(buf));
	return;
}

static int sigsys_handler_install(void) {
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

static int setup_vm_kvm_ioctl(int kvm_fd, int vm_fd) {
	int ret;

	/* kvm_fd */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
			SCMP_A0(SCMP_CMP_EQ, kvm_fd));
	if(ret < 0)
		return -1;

	/* vm_fd */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
			SCMP_A0(SCMP_CMP_EQ, vm_fd));
	if(ret < 0)
		return -1;

	/* TODO filter based on:
	 * - Files (only allow /dev/kvm, vmfd, vcpufds
	 * - Operations made on each file
	 */

	return 0;
}

int uhyve_seccomp_add_vcpu_fd(int vcpu_fd) {
	int ret =  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
			SCMP_A0(SCMP_CMP_EQ, vcpu_fd));
	if(ret < 0)
		return -1;
	return 0;
}

int uhyve_seccomp_init(int kvm_fd, int vm_fd) {
	int ret;

	printf("init seccomp\n");

	if(sigsys_handler_install())
		return -1;

	/* replace the parameter here with SCMP_ACT_KILL for full security */
	ctx = seccomp_init(SCMP_ACT_TRAP);
	if(ctx == NULL) {
		fprintf(stderr, "cannot init seccomp\n");
		return -1;
	}

	ALLOW_RULE(read);
	ALLOW_RULE(write);
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
	ALLOW_RULE(mmap);
	ALLOW_RULE(pread64);
	ALLOW_RULE(futex);
	ALLOW_RULE(tgkill);
	ALLOW_RULE(getpid);

	if(setup_vm_kvm_ioctl(kvm_fd, vm_fd))
		goto out;

	return 0;

out:
	fprintf(stderr, "Error adding rule to seccomp filter\n");
	seccomp_release(ctx);
	return -1;
}

int uhyve_seccomp_load(void) {
	int ret;

	ret = seccomp_load(ctx);
	if(ret < 0) {
		fprintf(stderr, "Error loading seccomp rules\n");
		return -1;
	}

	seccomp_release(ctx);
	return 0;
}
