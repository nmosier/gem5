#include "bbv.hh"

void
BBVTrace::reset()
{
    for (auto &[addr, block] : blocks)
        block.reset();
}

BBVBlock *
BBVTrace::block(ADDRINT addr)
{
    const auto it = blocks.try_emplace(addr).first;
    return &it->second;
}
