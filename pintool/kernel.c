#include <stdint.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <sys/prctl.h>
#include <asm/prctl.h>

#define STDERR_FILENO 2

#include "cpu/pin/message.hh"
#include "syscall.h"
#include "printf.h"
#include "ops.hh"
#include "libc.h"

#ifdef printf
# undef printf
#endif
#define printf(...) do { } while (0)

// FIXME: Virtual
#define vsyscall_base 0xffffffffff600000ULL
#define vsyscall_end (vsyscall_base + 0x1000)

const bool enable_logging = false;

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
    if (enable_logging)
        write(STDERR_FILENO, &c, 1);
}

void msg_read(Message *msg) {
    printf("KERNEL: reading request\n");
    read_all(req_fd, msg, sizeof *msg);
    printf("KERNEL: read request\n");
}

void msg_write(const Message *msg) {
    // printf("KERNEL: writing response\n");
    write_all(resp_fd, msg, sizeof *msg);
    // printf("KERNEL: wrote response\n");
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

          case GetReg:
            printf("KERNEL: handling GET_REG request\n");
            pinop_get_reg(msg.reg.name, msg.reg.data, msg.reg.size);
            msg.type = SetReg;
            msg_write(&msg);
            break;

          case Map:
            {
                // Check if vsyscall. This is special case.
                bool is_vsyscall = false;
                if (msg.map.vaddr == vsyscall_base) {
                    printf("KERNEL: fixing up vsyscall mapping 0x%" PRIx64 "->0x%" PRIx64 "\n",
                           msg.map.vaddr, msg.map.paddr);
                    msg.map.vaddr = 0xcafebabe000;
                    is_vsyscall = true;
                }
                
                void *map;
                if ((map = mmap((void *) msg.map.vaddr, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_SHARED | MAP_FIXED, mem_fd, msg.map.paddr)) == MAP_FAILED) {
                    printf("error: mmap failed (%d): vaddr=%p\n", errno, msg.map.vaddr);
                    pinop_abort();
                }
                if (map != (void *) msg.map.vaddr) {
                    printf("error: mmap mapped wrong address\n");
                    pinop_abort();
                }
                printf("mapped page: %p->%p (first byte: %02hhx)\n", (void *) msg.map.vaddr, (void *) msg.map.paddr, * (uint8_t *) map);
                if (is_vsyscall) {
                    pinop_set_vsyscall_base((void *) vsyscall_base, map);
                }
                msg.type = Ack;
                msg_write(&msg);
            }
            break;

          case Run:
            {
                printf("KERNEL handling RUN request\n");
                struct RunResult result;
                pinop_run(&result);
                Message msg;
                msg.inst_count = pinop_get_instcount();
                switch (result.result) {
                  case RUNRESULT_PAGEFAULT:
                    // Send this up to gem5.
                    printf("KERNEL: got page fault: %" PRIx64 "\n", result.addr);
                    msg.type = PageFault;
                    msg.faultaddr = result.addr;
                    break;

                  case RUNRESULT_SYSCALL:
                    // Send this up to gem5.
                    msg.type = Syscall;
                    break;

                  case RUNRESULT_CPUID:
                    // Send up to gem5.
                    msg.type = Cpuid;
                    break;
                    
                  default:
                    printf("KERNEL ERROR: unhandled run result: %d\n", result);
                    pinop_abort();
                }

                msg_write(&msg);
            }
            break;

          case Exit:
            exit(0);

          default:
            printf("error: bad message type (%d)\n", msg.type);
            pinop_abort();
        }

        // printf("KERNEL: handled message, going on to next iteration\n");
    }
}

void main(void) {
    char path[256];

    printf("KERNEL: starting up\n");
    
    // Open request file.
    pinop_get_reqpath(path, sizeof path);
    if ((req_fd = open(path, O_RDONLY)) < 0) {
        printf("error: open failed: %s (%d)\n", path, errno);
        pinop_abort(); 
    }

    printf("KERNEL: opened request file\n");
    
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
