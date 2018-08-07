#include "uhyve-seccomp.h"

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <linux/kvm.h>

#define DENY_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_KILL, SCMP_SYS(call), 0) < 0) goto out; }
#define ALLOW_RULE(call) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 0) < 0) goto out; }

#define ALLOW_IOCTL(fd, cmd) { if (seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 2, SCMP_A0(SCMP_CMP_EQ, fd), SCMP_A1(SCMP_CMP_EQ, cmd)) < 0) goto out; }

scmp_filter_ctx ctx;

void sigsys_handler(int signum, siginfo_t *siginfo, void *context) {
	char buf[256];
	sprintf(buf, "Seccomp - unauthorized syscall: %d\n", siginfo->si_syscall);
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

static int setup_vm_kvm_ioctl(int vm_fd) {
	int ret;

	/* While the guest is running, only these are needed in case of
	 * checkpointing */
	ALLOW_IOCTL(vm_fd, KVM_GET_CLOCK);
	ALLOW_IOCTL(vm_fd, KVM_GET_DIRTY_LOG);

	return 0;

out:
	fprintf(stderr, "Error setting up ioctl vm_fd seccomp rule\n");
	return -1;
}

int uhyve_seccomp_add_vcpu_fd(int vcpu_fd) {

	/* While the guest is running, only KVM_RUN and KVM_GET_REGS/SREGS are
	 * needed. However, for GDB debugging a few mores are also required */
	ALLOW_IOCTL(vcpu_fd, KVM_RUN);
	ALLOW_IOCTL(vcpu_fd, KVM_GET_REGS);
	ALLOW_IOCTL(vcpu_fd, KVM_SET_REGS);
	ALLOW_IOCTL(vcpu_fd, KVM_SET_SREGS);
	ALLOW_IOCTL(vcpu_fd, KVM_GET_SREGS);
	ALLOW_IOCTL(vcpu_fd, KVM_SET_GUEST_DEBUG);
	ALLOW_IOCTL(vcpu_fd, KVM_TRANSLATE);

	return 0;

out:
	fprintf(stderr, "Error setting up ioctl vcpu_fd seccomp rule\n");
	return -1;

}

int uhyve_seccomp_init(int vm_fd) {
	int ret;

	if(sigsys_handler_install())
		return -1;

	/* replace the parameter here with SCMP_ACT_KILL for full security */
	ctx = seccomp_init(SCMP_ACT_TRAP);
	if(ctx == NULL) {
		fprintf(stderr, "cannot init seccomp\n");
		return -1;
	}

	ALLOW_RULE(read);
	ALLOW_RULE(open);
	ALLOW_RULE(write);
	ALLOW_RULE(close);
	ALLOW_RULE(openat);
	ALLOW_RULE(lstat);
	ALLOW_RULE(lseek);
	ALLOW_RULE(mkdir);
	ALLOW_RULE(rmdir);
	ALLOW_RULE(getcwd);
	ALLOW_RULE(access);
	ALLOW_RULE(readlink);
	ALLOW_RULE(unlink);

	if(setup_vm_kvm_ioctl(vm_fd))
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
