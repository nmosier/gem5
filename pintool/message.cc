#include "cpu/pin/message.hh"

#include <iostream>
#include <cstdlib>

#include "pin.H"

namespace gem5
{

namespace pin
{

void
Message::send(int fd) const
{
    const uint8_t *data = reinterpret_cast<const uint8_t *>(this);
    size_t size = sizeof *this;
    if (OS_WriteFD(fd, data, &size).generic_err != OS_RETURN_CODE_NO_ERROR) {
        std::cerr << "error: OS_WriteFD failed\n";
        std::abort();
    }
    if (size != sizeof *this) {
        std::cerr << "error: OS_WriteFD: partial write\n";
        std::abort();
    }
}

void
Message::recv(int fd)
{
    uint8_t *data = reinterpret_cast<uint8_t *>(this);
    size_t size = sizeof *this;
    if (OS_ReadFD(fd, &size, data).generic_err != OS_RETURN_CODE_NO_ERROR) {
        std::cerr << "error: OS_ReadFD failed\n";
        std::abort();
    }
    if (size != sizeof *this) {
        std::cerr << "error: OS_ReadFD: partial read\n";
        std::abort();
    }
}

}
}
