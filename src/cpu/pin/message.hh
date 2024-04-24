#pragma once

#ifdef __cplusplus

namespace gem5
{

namespace pin
{

#endif

struct Message
{
    enum Type
    {
        Ack = 0,
        Map,
	SetReg,
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
    };

#ifdef __cplusplus
    void send(int fd) const;
    void recv(int fd);
#endif
};

#ifdef __cplusplus
}
}
#endif
