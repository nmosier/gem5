#pragma once

#include <cstddef>

namespace gem5
{

/*
 * The host kernel's KVM, reached through /dev/kvm.  Only api.cc calls these;
 * everything else goes through kvm_api:: so that it does not have to care
 * which backend is in use.  Declared here rather than in api.hh so that the
 * host sys headers stay inside api_kvm.cc.
 */

int kvm_open();
int kvm_close(int fd);
int kvm_ioctl(int fd, int request, long p1);
void *kvm_mmap(int fd, size_t len);
int kvm_munmap(void *addr, size_t len);

}
