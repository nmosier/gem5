#pragma once

#include <cstdint>

enum class PinOp
{
    SET_REG = 0,
    GET_CPUPATH = 1,
    GET_MEMPATH = 2,
    ABORT = 3,
    EXIT = 4,
    NumOps,
};

constexpr uintptr_t pinops_addr_base = static_cast<uint64_t>(0xbaddecaf) << 32;
constexpr uintptr_t pinops_addr_setreg = pinops_addr_base + static_cast<unsigned>(PinOp::SET_REG);
constexpr uintptr_t pinops_addr_end = pinops_addr_base + static_cast<unsigned>(PinOp::NumOps);

static inline bool is_pinop_addr(void *p)
{
    const uintptr_t s = (uintptr_t) p;
    return pinops_addr_base <= s && s < pinops_addr_end;
}
