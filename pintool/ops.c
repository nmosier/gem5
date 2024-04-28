#include "ops.hh"

// TODO: macro for defining these, since they are all basically the same.

void __attribute__((naked)) pinop_set_reg(const char *name, const uint8_t *data, size_t size) {
    asm volatile ("movb $0, (%0)\nret\n"
		  :: "r"(pinops_addr_base + OP_SET_REG));
}

void __attribute__((naked)) pinop_get_reg(const char *name, uint8_t *data, size_t size) {
    asm volatile ("movb $0, (%0)\nret\n"
		  :: "r"(pinops_addr_base + OP_GET_REG));
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

void __attribute__((naked)) pinop_set_vsyscall_base(void *virt, void *phys) {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_SET_VSYSCALL_BASE));
}

uint64_t __attribute__((naked)) pinop_get_instcount(void) {
    asm volatile ("movb $0, (%0)\nret\n" :: "r"(pinops_addr_base + OP_GET_INSTCOUNT));
}
