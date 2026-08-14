#include "cpu/kvm/api.hh"

#include "base/logging.hh"
#include "config/use_host_kvm.hh"
#include "config/use_qvm.hh"

#if USE_HOST_KVM
#include "cpu/kvm/api_kvm.hh"

#endif
#if USE_QVM
#include "cpu/kvm/api_qvm.hh"

#endif

namespace gem5
{

namespace kvm_api
{

/*
 * Both backends are optional and independent: a Linux host without QVM has
 * only the first, a host QEMU can emulate but Linux cannot run on has only
 * the second, and a Linux host with QVM configured has both.  Asking for one
 * that was not built is a configuration error rather than a runtime failure,
 * so it panics with an explanation instead of returning -1.
 */
static void
require(bool qemu)
{
    if (!available(qemu)) {
        panic("KVM: the %s backend is not compiled into this gem5. %s",
              name(qemu),
              qemu ? "Rebuild with QVM_PATH pointing at a configured QEMU "
                     "source tree, or unset the 'qemu' parameter."
                   : "This host has no usable /dev/kvm; set the 'qemu' "
                     "parameter to run on QVM instead.");
    }
}

bool
available(bool qemu)
{
    return qemu ? (bool)USE_QVM : (bool)USE_HOST_KVM;
}

const char *
name(bool qemu)
{
    return qemu ? "QVM" : "host KVM";
}

int
open(bool qemu)
{
    require(qemu);
#if USE_QVM
    if (qemu) {
        return qvm_open();
    }
#endif
#if USE_HOST_KVM
    return kvm_open();
#else
    return -1;
#endif
}

int
close(bool qemu, int fd)
{
    require(qemu);
#if USE_QVM
    if (qemu) {
        return qvm_close(fd);
    }
#endif
#if USE_HOST_KVM
    return kvm_close(fd);
#else
    return -1;
#endif
}

int
ioctl(bool qemu, int fd, int request, long p1)
{
    require(qemu);
#if USE_QVM
    if (qemu) {
        return qvm_ioctl(fd, request, p1);
    }
#endif
#if USE_HOST_KVM
    return kvm_ioctl(fd, request, p1);
#else
    return -1;
#endif
}

void *
mmap(bool qemu, int fd, size_t len)
{
    require(qemu);
#if USE_QVM
    if (qemu) {
        return qvm_mmap(fd, len);
    }
#endif
#if USE_HOST_KVM
    return kvm_mmap(fd, len);
#else
    return nullptr;
#endif
}

int
munmap(bool qemu, void *addr, size_t len)
{
    require(qemu);
#if USE_QVM
    if (qemu) {
        return qvm_munmap(addr, len);
    }
#endif
#if USE_HOST_KVM
    return kvm_munmap(addr, len);
#else
    return -1;
#endif
}

} // namespace kvm_api

} // namespace gem5
