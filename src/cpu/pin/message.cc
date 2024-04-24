#include "cpu/pin/message.hh"

#include <sstream>
#include <cstdlib>
#include <unistd.h>

namespace gem5
{

namespace pin
{

void
Message::send(int fd) const
{
    const uint8_t *data = reinterpret_cast<const uint8_t *>(this);
    size_t size = sizeof *this;
    while (size > 0) {
        ssize_t bytes_written;
        if ((bytes_written = write(fd, data, size)) < 0)
            std::abort();
        data += bytes_written;
        size -= bytes_written;
    }
}

void
Message::recv(int fd)
{
    uint8_t *data = reinterpret_cast<uint8_t *>(this);
    size_t size = sizeof *this;
    while (size > 0) {
        ssize_t bytes_read;
        if ((bytes_read = read(fd, data, size)) < 0)
            std::abort();
        data += bytes_read;
        size -= bytes_read;
    }
}

}
}
