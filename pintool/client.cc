#include <cstdlib>
#include <iostream>
#include <string>
#include <fstream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unordered_map>

#include "pin.H"
#include "ops.hh"

static const char *prog;
static KNOB<std::string> log_path(KNOB_MODE_WRITEONCE, "pintool", "log", "", "specify path to log file");
static std::ofstream log_;
static CONTEXT user_ctx;
static CONTEXT saved_kernel_ctx;
static KNOB<std::string> cpu_path(KNOB_MODE_WRITEONCE, "pintool", "cpu_path", "", "specify path to CPU communciation FIFO");
static KNOB<std::string> mem_path(KNOB_MODE_WRITEONCE, "pintool", "mem_path", "", "specify path to physmem file");

#define ENTRY_ADDR ((ADDRINT) 0xdeadbeef0000000)
#define SYSCALL_ADDR ((ADDRINT) 0xdeadbeef000000a)

static void
Abort()
{
    log_.close();
    std::abort();
}

static std::string
CopyUserString(ADDRINT addr)
{
    std::string s;
    while (true) {
        char c;
        // TODO: Consider using PIN_SafeCopyEx.
        if (PIN_SafeCopy(&c, (const void *) addr, 1) != 1) {
            log_ << "error: failed to copy user string\n";
            Abort();
        }
        if (c == '\0')
            break;
    }
    return s;
}

static void
CheckPinOps(ADDRINT effaddr, CONTEXT *kernel_ctx_ptr, uint32_t inst_size)
{
    if (is_pinop_addr((void *) effaddr)) {
        // Don't save kernel context by default. But do skip over PinOp.
        ADDRINT pc = PIN_GetContextReg(kernel_ctx_ptr, REG_RIP);
        pc += inst_size;
        PIN_SetContextReg(kernel_ctx_ptr, REG_RIP, pc);
        log_ << "inst size: " << inst_size << "\n";

        PinOp op = (PinOp) (effaddr - (uintptr_t) pinops_addr_base);
        switch (op) {
          case PinOp::SET_REG:
            {
                // Get register name (held in rax).
                const std::string regname = CopyUserString(PIN_GetContextReg(&user_ctx, REG_RAX));
                static const std::unordered_map<std::string, REG> name_to_reg = {
                };
                const auto it = name_to_reg.find(regname);
                if (it == name_to_reg.end()) {
                    log_ << "error: failed to translate \"" << regname << "\" to Pin REG\n";
                    Abort();
                }
                const REG reg = it->second;
                const ADDRINT user_data = PIN_GetContextReg(&user_ctx, REG_RCX);
                const ADDRINT user_size = PIN_GetContextReg(&user_ctx, REG_RDX);
                std::vector<uint8_t> buf(user_size);
                if (PIN_SafeCopy(buf.data(), (const void *) user_data, buf.size()) != buf.size()) {
                    log_ << "error: failed to copy register data\n";
                    Abort();
                }
                assert(buf.size() == REG_Size(reg));
                PIN_SetContextRegval(&user_ctx, reg, buf.data());
                PIN_ExecuteAt(kernel_ctx_ptr);
            }
            break;

          case PinOp::GET_CPUPATH:
          case PinOp::GET_MEMPATH:
            {
                std::string path;
                if (op == PinOp::GET_CPUPATH) {
                    path = cpu_path.Value();
                } else if (op == PinOp::GET_MEMPATH) {
                    path = mem_path.Value();
                } else {
                    log_ << "Bad path PinOp\n";
                    Abort();
                }
                path.push_back('\0');
                
                const ADDRINT kernel_data = PIN_GetContextReg(kernel_ctx_ptr, REG_RDI);
                const ADDRINT kernel_size = PIN_GetContextReg(kernel_ctx_ptr, REG_RSI);
                if (path.size() > kernel_size) {
                    log_ << "PinOp GET_CPUPATH: CPU path does not fit in kernel buffer (" << kernel_size << " bytes)\n";
                    Abort();
                }
                if (PIN_SafeCopy((void *) kernel_data, path.data(), path.size()) != path.size()) {
                    log_ << "PinOp GET_CPUPATH: failed to copy\n";
                    Abort();
                }
		log_ << "Serived GET_CPUPATH\n";
                PIN_ExecuteAt(kernel_ctx_ptr);
            }
            break;

          case PinOp::EXIT:
            log_ << "Got EXIT\n";
            PIN_ExitApplication(0);
            break;

          case PinOp::ABORT:
            log_ << "Got ABORT\n";
            PIN_ExitApplication(1);
            break;

          default:
            log_ << "invalid pinop: " << (int) op << "\n";
            Abort();
        }

    }
}



static void
Instruction(INS ins, void *)
{
    static bool kernel_valid = false;
    static uint64_t kernel_start, kernel_end;
    if (!kernel_valid) {
        IMG img = APP_ImgHead();
        assert(IMG_Valid(img));
        assert(IMG_IsMainExecutable(img));
        assert(IMG_IsStaticExecutable(img));
        kernel_start = IMG_LowAddress(img);
        kernel_end = IMG_HighAddress(img);
    }

    const ADDRINT addr = INS_Address(ins);
    if (kernel_start <= addr && addr < kernel_end &&
	INS_MemoryOperandCount(ins) > 0) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckPinOps,
                       IARG_MEMORYOP_EA, 0,
                       IARG_CONTEXT,
                       IARG_UINT32, INS_Size(ins),
                       IARG_END);
    }
}

static void
usage(std::ostream &os)
{
    std::cerr << prog << ": gem5 pin CPU client\n";
    std::cerr << KNOB_BASE::StringKnobSummary() << "\n";
}

static void Fini(int32_t code, void *) {
    std::cerr << "Exiting: code = " << code << "\n";
    log_ << prog << ": Finished running the program, Pin exiting!\n";
    log_.close();
}

int
main(int argc, char *argv[])
{
    prog = argv[0];
    if (PIN_Init(argc, argv)) {
        usage(std::cerr);
        return EXIT_FAILURE;
    }

    if (log_path.Value().empty()) {
        std::cerr << "error: required option: -log\n";
        return EXIT_FAILURE;
    }
    log_.open(log_path.Value());

    if (cpu_path.Value().empty()) {
        std::cerr << "error: required option: -cpu_path\n";
        return EXIT_FAILURE;
    }
    OS_FILE_ATTRIBUTES attr;
    if (OS_GetFileAttributes(cpu_path.Value().c_str(), &attr).generic_err != OS_RETURN_CODE_NO_ERROR) {
        std::cerr << "error: failed to open file: " << cpu_path.Value() << "\n";
        return EXIT_FAILURE;
    }

    if (mem_path.Value().empty()) {
        std::cerr << "error: required option: -mem_path\n";
        return EXIT_FAILURE;
    }
    if (OS_GetFileAttributes(mem_path.Value().c_str(), &attr).generic_err != OS_RETURN_CODE_NO_ERROR) {
        std::cerr << "error: failed to open file: " << mem_path.Value() << "\n";
        return EXIT_FAILURE;
    }

    INS_AddInstrumentFunction(Instruction, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    std::cerr << "runtime: starting program\n";

    PIN_StartProgram();
}
