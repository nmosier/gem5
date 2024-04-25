#pragma once

#ifdef __cplusplus
# include <cstdint>
# include <ostream>
#else
# include <stdint.h>
#endif

#ifdef __cplusplus

namespace gem5
{

namespace pin
{

#endif

// TODO: Split up into separate requests and respones.
struct __attribute__((packed)) Message
{
    enum Type
    {
        Ack = 0,
        Map,
	SetReg,
        Abort,
        Run,
        PageFault,
        Syscall,
        GetReg,
        Cpuid,
        NumTypes
    } type;
    union
    {
        struct
        {
            // TODO: Use gem5 Addr.
            uint64_t vaddr;
            uint64_t paddr;
        } map; // For Type::Map

        struct
        {
            char name[63];
            uint8_t size;
            uint8_t data[64];
        } reg; // For Type::SetReg

        uint64_t faultaddr; // for PageFault
    };

#ifdef __cplusplus
    void send(int fd) const;
    void recv(int fd);
#endif
};

#ifdef __cplusplus
std::ostream &operator<<(std::ostream &os, const Message &msg);
#endif

#ifdef __cplusplus
}
}
#endif
