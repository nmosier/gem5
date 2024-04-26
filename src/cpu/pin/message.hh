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
        Invalid = 0,
        Ack,
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

    uint64_t inst_count; // Valid for all responses to RUN requests.
    
#ifdef __cplusplus
    // TODO: Make these members of the pin::CPU class or the PinProcess class.
    void send(int sockfd) const;
    void recv(int sockfd);
#endif
};

#ifdef __cplusplus
std::ostream &operator<<(std::ostream &os, const Message &msg);
#endif

#ifdef __cplusplus
}
}
#endif
