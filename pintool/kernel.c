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
#include "ops.hh"

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


void __attribute__((naked)) pinop_set_reg(const char *name, const uint8_t *data, size_t size) {
    asm volatile ("movb $0, (%0)\nret\n"
		  :: "r"(pinops_addr_base + OP_SET_REG));
}

void __attribute__((naked)) pinop_get_reqpath(char *data, size_t size) {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_GET_REQPATH));
}

void __attribute__((naked)) pinop_get_resppath(char *data, size_t size) {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_GET_RESPPATH));
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

void __attribute__((naked)) pinop_resetuser() {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_RESETUSER));
}

void __attribute__((naked)) pinop_run(struct RunResult *result) {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_RUN));
}


static const char *prog;
static int req_fd;
static int resp_fd;
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
    printf("KERNEL: reading request\n");
    read_all(req_fd, msg, sizeof *msg);
    printf("KERNEL: read request\n");
}

void msg_write(const Message *msg) {
    printf("KERNEL: writing response\n");
    write_all(resp_fd, msg, sizeof *msg);
    printf("KERNEL: wrote response\n");
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
            printf("KERNEL: handling SET_REG request\n");
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
                printf("mapped page: %p->%p (first byte: %02hhx)\n", (void *) msg.map.vaddr, (void *) msg.map.paddr, * (uint8_t *) map);
                msg.type = Ack;
                msg_write(&msg);
            }
            break;

          case Run:
            {
                printf("KERNEL handlinkg RUN request\n");
                struct RunResult result;
                pinop_run(&result);
                switch (result.result) {
                  case RUNRESULT_PAGEFAULT:
                    // Send this up to gem5.
                    {
                        Message msg;
                        msg.type = PageFault;
                        msg.faultaddr = result.addr;
                        msg_write(&msg);
                    }
                    break;
                    
                  default:
                    printf("KERNEL ERROR: unhandled run result: %d\n", result);
                    pinop_abort();
                }
            }
            break;

          default:
            printf("error: bad message type (%d)\n", msg.type);
            pinop_abort();
        }

        printf("KERNEL: handled message, going on to next iteration\n");
    }
}

void main(void) {
    char path[256];
    
    // Open request file.
    pinop_get_reqpath(path, sizeof path);
    if ((req_fd = open(path, O_RDONLY)) < 0) {
        printf("error: open failed: %s (%d)\n", path, errno);
        pinop_abort(); 
    }

    // Open response file.
    pinop_get_resppath(path, sizeof path);
    if ((resp_fd = open(path, O_WRONLY)) < 0) {
        printf("error: open failed: %s (%d)\n", path, errno);
        pinop_abort();
    }

    // Open physmem file.
    char mem_path[256];
    pinop_get_mempath(mem_path, sizeof mem_path);
    if ((mem_fd = open(mem_path, O_RDWR)) < 0) {
        printf("error: open failed: %s (%d)\n", mem_path, errno);
        pinop_abort();
    }

    // Initialize user context.
    pinop_resetuser();

    main_event_loop();

    pinop_exit(0);
}
