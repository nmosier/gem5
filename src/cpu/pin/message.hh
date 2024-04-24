#pragma once

#include <string>

namespace gem5
{

namespace pin
{

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
            char name[24];
            uint64_t value;
        } reg; // For Type::SetReg
    };

    std::string serialize() const;
    void deserialize(const std::string &s);
    void send(int fd) const;
    void recv(int fd);
};

}
}
