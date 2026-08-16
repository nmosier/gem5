#pragma once

#include <cstddef>
#include <cstdint>

namespace gem5
{

/*
 * QVM: the same API implemented in userspace on top of QEMU's system-mode
 * TCG, so that a KVM CPU can run without /dev/kvm and without the host ISA
 * matching the simulated one.  See <qemu>/qvm/README.md.
 *
 * As with api_kvm.hh, only api.cc calls these.
 */

int qvm_open();
int qvm_close(int fd);
int qvm_ioctl(int fd, int request, long p1);
void *qvm_mmap(int fd, size_t len);
int qvm_munmap(void *addr, size_t len);
int qvm_load_plugin(const char *path, const char *args);
uint64_t qvm_vcpu_insns(int fd);
int qvm_vcpu_set_insn_budget(int fd, uint64_t insns);

}
