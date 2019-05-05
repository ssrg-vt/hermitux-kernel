#include <hermit/syscall.h>
#include <hermit/logging.h>
#include <asm/processor.h>

#define ARCH_SET_GS			0x1001
#define ARCH_SET_FS			0x1002
#define ARCH_GET_FS			0x1003
#define ARCH_GET_GS			0x1004

#define ARCH_GET_CPUID		0x1011
#define ARCH_SET_CPUID		0x1012

#define ARCH_MAP_VDSO_X32	0x2001
#define ARCH_MAP_VDSO_32	0x2002
#define ARCH_MAP_VDSO_64	0x2003

int sys_arch_prctl(int option, unsigned long *arg2, unsigned long *addr) {
#ifndef __aarch64__
	switch(option) {
		case ARCH_SET_GS:
			writegs((uint64_t)arg2);
			return 0;

		case ARCH_SET_FS:
			writefs((uint64_t)arg2);
			return 0;

		case ARCH_GET_GS: {
			unsigned long gs_val = readgs();
			*arg2 = gs_val;
			return 0;
		}

		case ARCH_GET_FS: {
			unsigned long fs_val = readfs();
			*arg2 = fs_val;
			return 0;
		}

		case ARCH_GET_CPUID:
			LOG_ERROR("arch_prctl option GET_CPUID not implemented\n");
			return -ENOSYS;

		case ARCH_SET_CPUID:
			LOG_ERROR("arch_prctl option SET_CPUID not implemented\n");
			return -ENOSYS;

		case ARCH_MAP_VDSO_X32:
			LOG_ERROR("arch_prctl option MAP_VDSO_X32 not implemented\n");
			return -ENOSYS;

		case ARCH_MAP_VDSO_32:
			LOG_ERROR("arch_prctl option MAP_VDSO_32 not implemented\n");
			return -ENOSYS;

		case ARCH_MAP_VDSO_64:
			LOG_ERROR("arch_prctl option MAP_VDSO_64 not implemented\n");
			return -ENOSYS;

		default:
			LOG_ERROR("arch_prctl: unknown option 0x%x\n", option);
			return -EINVAL;
	}
#endif

	return -ENOSYS;
}

