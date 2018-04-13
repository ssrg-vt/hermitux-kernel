#include <hermit/syscall.h>
#include <hermit/signal.h>

typedef void * siginfo_t;
typedef void * sigset_t;

struct sigaction {
	union {
		void (*sa_handler)(int);
		void (*sa_sigaction)(int, siginfo_t *, void *);
	};
	sigset_t sa_mask;
	int sa_flags;
	void (*sa_restorer)(void);
};

#define MAX_SIGNUM 32

struct sigaction *installed_sigactions[MAX_SIGNUM];

int sys_rt_sigaction(int signum, struct sigaction *act,
		struct sigaction *oldact) {

	if(oldact)
		oldact = installed_sigactions[signum];

	if(act) {
		signal_handler_t sa = act->sa_handler;
		hermit_signal(sa);
		installed_sigactions[signum] = act;
	}

	return 0;
}
