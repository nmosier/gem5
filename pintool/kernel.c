#include <stdint.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

#define STDERR_FILENO 2

#include "cpu/pin/message.hh"
#include "syscall.h"
#include "printf.h"

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


const uint64_t pinops_addr_base = (uint64_t) 0xbaddecaf << 32;

enum pinop {
    OP_SET_REG = 0,
    OP_GET_CPUPATH = 1,
    OP_GET_MEMPATH = 2,
    OP_ABORT = 3,
    OP_EXIT = 4,
};

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



static const char *prog;
static int cpu_fd;
static int mem_fd;

typedef struct Message Message;


void read_all(int fd, void *data_, size_t size) {
    char *data = (char *) data_;
    while (size) {
        const ssize_t bytes_read = read(fd, data, size);
        if (bytes_read < 0) {
            printf("error: read failed (%d)\n", errno);
            pinop_abort();
        }
        data += bytes_read;
        size -= bytes_read;
    }
}

void write_all(int fd, const void *data_, size_t size) {
    const char *data = (const char *) data_;
    while (size) {
        const ssize_t bytes_written = write(fd, data, size);
        if (bytes_written < 0) {
            printf("error: write failed (%d)\n", errno);
            pinop_abort();
        }
        data += bytes_written;
        size -= bytes_written;
    }
}

void _putchar(char c) {
    write(STDERR_FILENO, &c, 1);
}

void msg_read(Message *msg) {
    printf("note: waiting to read message\n");
    read_all(cpu_fd, msg, sizeof *msg);
}

void msg_write(const Message *msg) {
    printf("note: writing message of type %d\n", msg->type);
    write_all(cpu_fd, msg, sizeof *msg);
}

void main_event_loop(void) {
    while (true) {
        Message msg;
        msg_read(&msg);

        switch (msg.type) {
          case Ack:
            msg_write(&msg);
            break;

          case SetReg:
            pinop_set_reg(msg.reg.name, msg.reg.data, msg.reg.size);
            msg.type = Ack;
            msg_write(&msg);
            break;

          case Map:
            {
                void *map;
                if ((map = mmap((void *) msg.map.vaddr, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_SHARED | MAP_FIXED, mem_fd, msg.map.paddr)) == MAP_FAILED) {
                    printf("error: mmap failed (%d)\n", errno);
                    pinop_abort();
                }
                if (map != (void *) msg.map.vaddr) {
                    printf("error: mmap mapped wrong address\n");
                    pinop_abort();
                }
                msg.type = Ack;
                msg_write(&msg);
            }
            break;

          default:
            printf("error: bad message type (%d)\n", msg.type);
            pinop_abort();
        }
    }
}

void main(void) {
    // Open CPU communication file.
    char cpu_path[256];
    pinop_get_cpupath(cpu_path, sizeof cpu_path);
    if ((cpu_fd = open(cpu_path, O_RDWR)) < 0) {
        printf("error: open failed: %s (%d)\n", cpu_path, errno);
        pinop_abort(); 
    }

    // Open physmem file.
    char mem_path[256];
    pinop_get_mempath(mem_path, sizeof mem_path);
    if ((mem_fd = open(mem_path, O_RDWR)) < 0) {
        printf("error: open failed: %s (%d)\n", mem_path, errno);
        pinop_abort();
    }

    main_event_loop();

    pinop_exit(0);
}
