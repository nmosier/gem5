#include "cpu/kvm/api_kvm.hh"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace gem5
{

int
kvm_open()
{
    return ::open("/dev/kvm", O_RDWR);
}

int
kvm_close(int fd)
{
    return ::close(fd);
}

int
kvm_ioctl(int fd, int request, long p1)
{
    return ::ioctl(fd, request, p1);
}

void *
kvm_mmap(int fd, size_t len)
{
    void *p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    return p == MAP_FAILED ? nullptr : p;
}

int
kvm_munmap(void *addr, size_t len)
{
    return ::munmap(addr, len);
}

}
