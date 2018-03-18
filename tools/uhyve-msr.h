#ifndef UHYVE_MSR_H
#define UHYVE_MSR_H

/* Starting from Linux 4.12, /msr-index.h is not anymore exported to userspace,
 * so let's put the defines needed for uhyve here */


#define _EFER_LME		8  /* Long mode enable */
#define EFER_LME		(1<<_EFER_LME)

#define MSR_IA32_APICBASE		0x0000001b
#define MSR_IA32_MISC_ENABLE		0x000001a0

#define MSR_IA32_SYSENTER_CS		0x00000174
#define MSR_IA32_SYSENTER_ESP		0x00000175
#define MSR_IA32_SYSENTER_EIP		0x00000176

#define MSR_IA32_CR_PAT			0x00000277

#define MSR_IA32_TSC			0x00000010

#define MSR_EFER		0xc0000080 /* extended feature register */
#define MSR_STAR		0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR		0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR		0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK	0xc0000084 /* EFLAGS mask for syscall */
#define MSR_FS_BASE		0xc0000100 /* 64bit FS base */
#define MSR_GS_BASE		0xc0000101 /* 64bit GS base */
#define MSR_KERNEL_GS_BASE	0xc0000102 /* SwapGS GS shadow */
#define MSR_TSC_AUX		0xc0000103 /* Auxiliary TSC */


#endif /* UHYVE_MSR_H */
