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
    };

    std::string serialize() const;
    void deserialize(const std::string &s);
    void send(int fd) const;
    void recv(int fd);
};

}
}
