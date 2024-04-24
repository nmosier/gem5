#include <stdint.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>

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
static int errno;

typedef struct Message Message;

void exit(int code) {
    asm volatile (
        "movl %0, %%eax\n"
        "movl %1, %%edi\n"
        "syscall\n"
        :: "i"(SYS_exit), "r"(code));
}

ssize_t write(int fd, const void *data, size_t size) {
    ssize_t result;
    asm volatile (
        "movl %1, %%eax\n"
        "movl %2, %%edi\n"
        "movq %3, %%rsi\n"
        "movq %4, %%rdx\n"
        "syscall\n"
        : "=a"(result)
        : "i"(SYS_write), "r"(fd), "r"(data), "r"(size));
    errno = result;
    return result;
}

int open_(const char *path, int flags, ...) {
    int result;
    asm volatile (
        "movl %1, %%eax\n"
        "movq %2, %%rdi\n"
        "movl %3, %%esi\n"
        "syscall\n"
        : "=a"(result)
        : "i"(SYS_open), "r"(path), "r"(flags));
    errno = result;
    return result;
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
    asm volatile ("movb $0, (%0)\nret\n"
		  :: "r"(pinops_addr_base + OP_SET_REG));
}

void __attribute__((naked)) pinop_get_cpupath(char *data, size_t size) {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_GET_CPUPATH));
}

void __attribute__((naked)) pinop_get_mempath(char *data, size_t size) {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_GET_MEMPATH));
}

void __attribute__((naked)) pinop_exit(int code) {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_EXIT));
}

void __attribute__((naked)) pinop_abort() {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_ABORT));
}

void main(void) {
    // Open CPU communication file.
    char cpu_path[256];
    pinop_get_cpupath(cpu_path, sizeof cpu_path);
    if ((cpu_fd = open_(cpu_path, O_RDWR)) < 0) {
        printf("error: open failed: %s (%d)\n", cpu_path, -errno);
        pinop_abort(); 
    }

    // Open physmem file.
    char mem_path[256];
    pinop_get_mempath(mem_path, sizeof mem_path);
    if ((mem_fd = open_(mem_path, O_RDWR)) < 0) {
        printf("error: open failed: %s (%d)\n", mem_path, -errno);
        pinop_abort();
    }

    pinop_exit(0);
}
