#include "cpu/pin/message.hh"

#include <cstdlib>
#include <unistd.h>

#include "base/logging.hh"
#include "debug/Pin.hh"

namespace gem5
{

namespace pin
{

void
Message::send(int fd) const
{
    // inform("sending message (type=%i)\n", type);
    const uint8_t *data = reinterpret_cast<const uint8_t *>(this);
    size_t size = sizeof *this;
    while (size > 0) {
        ssize_t bytes_written;
        if ((bytes_written = write(fd, data, size)) < 0)
            std::abort();
        data += bytes_written;
        size -= bytes_written;
    }
    // inform("sent message\n");
}

void
Message::recv(int fd)
{
    // inform("receiving message\n");
    type = (Type) -1;
    uint8_t *data = reinterpret_cast<uint8_t *>(this);
    size_t size = sizeof *this;
    while (size > 0) {
        ssize_t bytes_read;
        if ((bytes_read = read(fd, data, size)) < 0)
            std::abort();
        data += bytes_read;
        size -= bytes_read;
    }
    // inform("received message (type=%i)\n", type);
}

std::ostream &
operator<<(std::ostream &os, const Message &msg)
{
    os << "pinmsg{.type=";
    switch (msg.type) {
      case Message::Ack:
        os << "ACK";
        break;
      case Message::SetReg:
        os << "SET_REG, .name=" << msg.reg.name << ", .size=" << ((int) msg.reg.size) << ", .data=";
        for (size_t i = 0; i < msg.reg.size; ++i) {
            char buf[16];
            std::sprintf(buf, "%02hhx", msg.reg.data[i]);
            os << buf;
        }
        break;
      default:
        panic("unhandled message type!\n");
    }
    os << "}";
    return os;
}

}
}
