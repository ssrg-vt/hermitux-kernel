#ifndef UHYVE_SECCOMP_H
#define UHYVE_SECCOMP_H

int uhyve_seccomp_init(int vm_fd);
int uhyve_seccomp_load(void);
int uhyve_seccomp_add_vcpu_fd(int vcpu_fd);

#endif /* UHYVE_SECCOMP_H */
