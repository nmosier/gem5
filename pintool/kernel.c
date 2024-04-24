#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <err.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include "cpu/pin/message.hh"

static const char *prog;
static int cpu_fd;
static int mem_fd;

typedef struct Message Message;

static void
msg_recv(Message *msg)
{
    if (read(cpu_fd, msg, sizeof *msg) != sizeof *msg)
        errx(EXIT_FAILURE, "msg_recv: read failed");
}

static void
msg_send(const Message *msg)
{
    if (write(cpu_fd, msg, sizeof *msg) != sizeof *msg)
        errx(EXIT_FAILURE, "msg_send: write failed");
}

static void
unmap_pages(void)
{
    const unsigned long long unmap_below = 0x400000000000ULL;

    FILE *f;
    if ((f = fopen("/proc/self/maps", "r")) == NULL)
        err(EXIT_FAILURE, "fopen");

    char buf[1024];
    while (fgets(buf, sizeof buf, f)) {
        unsigned long long start, end;
        if (sscanf(buf, "%llx-%llx", &start, &end) != 2)
            errx(EXIT_FAILURE, "bad /proc/self/maps format: %s", buf);
        if (end <= unmap_below) {
            errx(EXIT_FAILURE, "encountered page in bad range: %llx-%llx", start, end);
            if (munmap((void *) start, end - start) < 0)
                err(EXIT_FAILURE, "munmap: %llx-%llx", start, end);
            fprintf(stderr, "unmapping %llx-%llx\n", start, end);
        } else {
            assert(start >= unmap_below);
        }
    }

    fclose(f);

    fprintf(stderr, "Done unmapping pages\n");
}

static void
process_map_command(const Message *msg)
{
    void *map;
    if ((map = mmap((void *) msg->map.vaddr, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED, mem_fd, msg->map.paddr)) == MAP_FAILED)
        err(EXIT_FAILURE, "mmap: vaddr=%" PRIx64 " paddr=%" PRIx64, msg->map.vaddr, msg->map.paddr);
    assert(map == (void *) msg->map.vaddr);
}

static void
pinops_exec_setreg(const char *name, const uint8_t *data, uint64_t size)
{
    asm volatile ("movb $0, (%0)" :: "a"(name), "c"(data), "d"(size));
}

static void
process_setreg_command(const Message *msg)
{
    pinops_exec_setreg(msg->reg.name, msg->reg.data, msg->reg.size);
}

static void
main_event_loop(void)
{
    while (true) {
        Message msg;
        msg_recv(&msg);

        switch (msg.type) {
          case Ack:
            msg.type = Ack;
            msg_send(&msg);
            break;

          case Map:
            process_map_command(&msg);
            msg.type = Ack;
            msg_send(&msg);
            break;

          case SetReg:
            process_setreg_command(&msg);
            msg.type = Ack;
            msg_send(&msg);
            break;

          default:
            errx(EXIT_FAILURE, "unhandled message type: %d", msg.type);
        }

    }
}

static void
usage(FILE *f)
{
    fprintf(f, "usage: %s comm_path mem_path\n", prog);
}

int
main(int argc, char *argv[])
{
    prog = argv[0];

    if (argc != 3) {
        usage(stderr);
        return EXIT_FAILURE;
    }

    // Unmap any stray pages.
    unmap_pages();

    // Open communication lines.
    if ((cpu_fd = open(argv[1], O_RDWR)) < 0)
        err(EXIT_FAILURE, "open: %s", argv[1]);
    if ((mem_fd = open(argv[2], O_RDWR)) < 0)
        err(EXIT_FAILURE, "open: %s", argv[1]);

    // Main event loop.
    main_event_loop();
}
