#include "cpu/kvm/api_qvm.hh"

#include <fcntl.h>
#include <qvm/qvm.h>
#include <sys/mman.h>

namespace gem5
{

/*
 * The unqualified names below are gem5's; the "::" ones are libqvm's.  QVM
 * descriptors are not host file descriptors, so they must only ever be passed
 * back to these functions.
 */

int
qvm_open()
{
    return ::qvm_open("/dev/kvm", O_RDWR);
}

int
qvm_close(int fd)
{
    return ::qvm_close(fd);
}

int
qvm_ioctl(int fd, int request, long p1)
{
    return ::qvm_ioctl(fd, (unsigned long)request, p1);
}

void *
qvm_mmap(int fd, size_t len)
{
    void *p = ::qvm_mmap(nullptr, len, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
    return p == MAP_FAILED ? nullptr : p;
}

int
qvm_munmap(void *addr, size_t len)
{
    return ::qvm_munmap(addr, len);
}

}
