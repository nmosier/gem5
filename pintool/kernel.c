#include <stdint.h>
#include <stdbool.h>
#include <sys/syscall.h>

#define NULL ((void *) 0)
#define STDERR_FILENO 2

#include "cpu/pin/message.hh"
#include "printf.h"

const uint64_t pinops_addr_base = (uint64_t) 0xbaddecaf << 32;

enum pinop {
    OP_SET_REG = 0,
    OP_GET_CPUPATH = 1,
    OP_GET_MEMPATH = 2,
    OP_ABORT = 3,
    OP_EXIT = 4,
};

static const char *prog;
static int cpu_fd;
static int mem_fd;

typedef struct Message Message;

void exit(int code) {
    asm volatile (
        "movl %0, %%eax\n"
        "movl %1, %%edi\n"
        "syscall\n"
        :: "i"(SYS_exit), "r"(code));
}

void write(int fd, const void *data, size_t size) {
    asm volatile (
        "mov %0, %%eax\n"
        "mov %1, %%edi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "syscall\n"
        :: "i"(SYS_write), "r"(fd), "r"(data), "r"(size));
}

static void
do_assert_failure(const char *file, int line, const char *desc)
{
    printf("%s:%d: assertion failed: %s\n", file, line, desc);
}

#define assert(pred) \
    do {             \
    if (!(pred))                                        \
        do_assert_failure(__FILE__, __LINE__, #pred);   \
    } while (false)

void _putchar(char c) {
    write(STDERR_FILENO, &c, 1);
}

void __attribute__((naked)) pinop_set_reg(const char *name, const uint8_t *data, size_t size) {
    asm volatile ("movb $0, (%0)" :: "r"(pinops_addr_base + OP_SET_REG));
}

void __attribute__((naked)) pinop_get_cpupath(char *data, size_t size) {
    asm volatile ("movb $0, (%0)" :: "r"(pinops_addr_base + OP_GET_CPUPATH));
}

void __attribute__((naked)) pinop_get_mempath(char *data, size_t size) {
    asm volatile ("movb $0, (%0)" :: "r"(pinops_addr_base + OP_GET_MEMPATH));
}

void __attribute__((naked)) pinop_exit(int code) {
    asm volatile ("movb $0, (%0)" :: "r"(pinops_addr_base + OP_EXIT));
}

void __attribute__((naked)) pinop_abort() {
    asm volatile ("movb $0, (%0)" :: "r"(pinops_addr_base + OP_ABORT));
}

void main(void) {
    pinop_exit(0);
}
