#pragma once

// TODO: This should just be ops.h, not ops.hh.

#ifdef __cplusplus
# include <cstdint>
#else
# include <stdint.h>
# include <stdbool.h>
# include <stddef.h>
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
    OP_GET_REG,
    OP_SET_VSYSCALL_BASE,
    OP_GET_INSTCOUNT,
    OP_COUNT,
};

#define pinops_addr_base ((uint64_t) 0xbaddecaf << 12)
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
        RUNRESULT_CPUID,
    } result;
    union {
        uint64_t addr; // RUNRESULT_PAGEFAULT
    };
};

// TODO: Only declare these in kernel, not pintool.
void pinop_set_reg(const char *name, const uint8_t *data, size_t size);
void pinop_get_reg(const char *name, uint8_t *data, size_t size);
void pinop_get_reqpath(char *data, size_t size);
void pinop_get_resppath(char *data, size_t size);
void pinop_get_mempath(char *data, size_t size);
void pinop_exit(int code);
void pinop_abort(void);
void pinop_resetuser(void);
void pinop_run(struct RunResult *result);
void pinop_set_vsyscall_base(void *virt, void *phys);
uint64_t pinop_get_instcount(void);
