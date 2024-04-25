#pragma once

#ifdef __cplusplus
# include <cstdint>
#else
# include <stdint.h>
#endif

enum PinOp
{
    OP_SET_REG,
    OP_GET_REQPATH,
    OP_GET_RESPPATH,
    OP_GET_MEMPATH,
    OP_ABORT,
    OP_EXIT,
    OP_RUN,
    OP_RESETUSER,
    OP_COUNT,
};

#define pinops_addr_base ((uint64_t) 0xbaddecaf << 32)
#define pinops_addr_end (pinops_addr_base + OP_COUNT)

static inline bool is_pinop_addr(void *p)
{
    const uintptr_t s = (uintptr_t) p;
    return pinops_addr_base <= s && s < pinops_addr_end;
}

struct RunResult {
    enum RunResultType {
        RUNRESULT_PAGEFAULT,
        RUNRESULT_SYSCALL,
    } result;
    union {
        uint64_t addr; // RUNRESULT_PAGEFAULT
    };
};
