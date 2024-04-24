#pragma once

#include <stdint.h>

constexpr char *pinops_addr_base = static_cast<uint64_t>(0xbaddecaf) << 32;
constexpr char *pinops_addr_setreg = pinops_base;
