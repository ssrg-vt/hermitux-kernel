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

int sys_rt_sigaction(int signum, const struct sigaction *act, 
		struct sigaction *oldact) {

	signal_handler_t sa = act->sa_handler;
	hermit_signal(sa);

	return 0;
}
