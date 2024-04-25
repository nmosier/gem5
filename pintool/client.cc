#include <cstdlib>
#include <iostream>
#include <string>
#include <fstream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unordered_map>
#include <unordered_set>

#include "pin.H"
#include "ops.hh"

static const char *prog;
static KNOB<std::string> log_path(KNOB_MODE_WRITEONCE, "pintool", "log", "", "specify path to log file");
static std::ofstream log_;
static CONTEXT user_ctx;
static CONTEXT saved_kernel_ctx;
static KNOB<std::string> req_path(KNOB_MODE_WRITEONCE, "pintool", "req_path", "", "specify path to CPU communciation FIFO");
static KNOB<std::string> resp_path(KNOB_MODE_WRITEONCE, "pintool", "resp_path", "", "specify path to response FIFO");
static KNOB<std::string> mem_path(KNOB_MODE_WRITEONCE, "pintool", "mem_path", "", "specify path to physmem file");
static std::unordered_set<ADDRINT> kernel_pages;

static void
Abort()
{
    log_.close();
    PIN_ExitApplication(1);
}

static ADDRINT getpage(ADDRINT addr) {
    return addr & ~(ADDRINT) 0xFFF;
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
        s.push_back(c);
        ++addr;
    }
    return s;
}

static void
CopyOutRunResult(CONTEXT *ctx, const RunResult &result)
{
    PIN_SafeCopy((RunResult *) PIN_GetContextReg(ctx, REG_RDI), &result, sizeof result);
}

static REG
ParseReg(const std::string &name)
{
    static const std::unordered_map<std::string, REG> name_to_reg = {
        // GPRs (16)
        {"rax", REG_RAX},
        {"rbx", REG_RBX},
        {"rcx", REG_RCX},
        {"rdx", REG_RDX},
        {"rdi", REG_RDI},
        {"rsi", REG_RSI},
        {"rbp", REG_RBP},
        {"rsp", REG_RSP},
        {"r8" , REG_R8 },
        {"r9" , REG_R9 },
        {"r10", REG_R10},
        {"r11", REG_R11},
        {"r12", REG_R12},
        {"r13", REG_R13},
        {"r14", REG_R14},
        {"r15", REG_R15},

        // Special
        {"rip", REG_RIP},
    };

    const auto it = name_to_reg.find(name);
    if (it == name_to_reg.end()) {
        std::cerr << "error: failed to translate \"" << name << "\" to Pin REG\n";
        Abort();
    }
    return it->second;
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
          case PinOp::OP_RESETUSER:
            PIN_SaveContext(kernel_ctx_ptr, &user_ctx);
            PIN_ExecuteAt(kernel_ctx_ptr);
            break;
            
          case PinOp::OP_SET_REG:
            {
                std::cerr << "CLIENT: handling SET_REG\n";
                // Get register name (held in rax).
                const std::string regname = CopyUserString(PIN_GetContextReg(kernel_ctx_ptr, REG_RDI));
                const REG reg = ParseReg(regname);
                const ADDRINT user_data = PIN_GetContextReg(kernel_ctx_ptr, REG_RSI);
                const uint8_t user_size = PIN_GetContextReg(kernel_ctx_ptr, REG_RDX);
                std::vector<uint8_t> buf(user_size);
                if (PIN_SafeCopy(buf.data(), (const void *) user_data, buf.size()) != buf.size()) {
                    std::cerr << "error: failed to copy register data\n";
                    Abort();
                }
                std::cerr << "SET_REG: name=" << regname << " size=" << ((int) user_size) << " ";
                if (user_size == 8) {
                    std::cerr << std::hex << "0x" << (* (uint64_t *) buf.data());
                } else {
                    for (int i = 0; i < user_size; ++i) {
                        char s[16];
                        std::sprintf(s, "%02hhx", buf[i]);
                        std::cerr << s;
                    }
                }
                std::cerr << "\n";
                    
                assert(buf.size() == REG_Size(reg));
                PIN_SetContextRegval(&user_ctx, reg, buf.data());
                PIN_ExecuteAt(kernel_ctx_ptr);
            }
            break;

          case PinOp::OP_GET_REG:
            {
                std::cerr << "CLIENT: handling GET_REG\n";
                const std::string regname = CopyUserString(PIN_GetContextReg(kernel_ctx_ptr, REG_RDI));
                const REG reg = ParseReg(regname);
                const ADDRINT user_data = PIN_GetContextReg(kernel_ctx_ptr, REG_RSI);
                const uint8_t user_size = PIN_GetContextReg(kernel_ctx_ptr, REG_RDX);
                std::vector<uint8_t> buf(user_size);
                assert(buf.size() == REG_Size(reg));
                PIN_GetContextRegval(&user_ctx, reg, buf.data());
                if (PIN_SafeCopy((void *) user_data, buf.data(), buf.size()) != buf.size()) {
                    std::cerr << "error: failed to copy register data to kernel\n";
                    Abort();
                }
                if (buf.size() == 8) {
                    std::cerr << "CLIENT: GET_REG " << regname << " <- " << std::hex << "0x" << (*(const uint64_t *)buf.data()) << "\n";
                }
                PIN_ExecuteAt(kernel_ctx_ptr);
            };
            break;
            

          case PinOp::OP_GET_REQPATH:
          case PinOp::OP_GET_RESPPATH:
          case PinOp::OP_GET_MEMPATH:
            {
                std::string path;
                switch (op) {
                  case OP_GET_REQPATH:
                    path = req_path.Value();
                    break;
                  case OP_GET_RESPPATH:
                    path = resp_path.Value();
                    break;
                  case OP_GET_MEMPATH:
                    path = mem_path.Value();
                    break;
                  default:
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

          case PinOp::OP_EXIT:
            log_ << "Got EXIT\n";
            PIN_ExitApplication(0);
            break;

          case PinOp::OP_ABORT:
            log_ << "Got ABORT\n";
            PIN_ExitApplication(1);
            break;

          case PinOp::OP_RUN:
            PIN_SaveContext(kernel_ctx_ptr, &saved_kernel_ctx);
            PIN_ExecuteAt(&user_ctx);
            std::abort();

          default:
            log_ << "invalid pinop: " << (int) op << "\n";
            Abort();
        }

    }
}


static void
HandleSyscall(CONTEXT *ctx, ADDRINT pc, uint32_t inst_size)
{
    std::cerr << "CLIENT: handling syscall: 0x" << std::hex << pc << "\n";
    assert(kernel_pages.count(getpage(pc)) == 0);
    PIN_SaveContext(ctx, &user_ctx);
    PIN_SaveContext(&saved_kernel_ctx, ctx);

    // Update PC.
    PIN_SetContextReg(&user_ctx, REG_RIP, pc);

    // Run result is syscall.
    RunResult result;
    result.result = RunResult::RUNRESULT_SYSCALL;
    CopyOutRunResult(ctx, result);
    PIN_ExecuteAt(ctx);
}

static void
TracePCs(ADDRINT inst)
{
    std::cerr << "TRACE: 0x" << std::hex << inst << "\n";
}

static void
Instruction(INS ins, void *)
{
    if (kernel_pages.empty()) {
        IMG img = APP_ImgHead();
        assert(IMG_Valid(img));
        assert(IMG_IsMainExecutable(img));
        assert(IMG_IsStaticExecutable(img));
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
            if (!SEC_Mapped(sec))
                continue;
            log_ << "section: " << std::hex << SEC_Address(sec) << "\n";
            const ADDRINT start = SEC_Address(sec);
            const ADDRINT end = start + SEC_Size(sec);
            for (ADDRINT page = start & ~(ADDRINT)0xFFF; page < end; page += 0x1000)
                kernel_pages.insert(page);
        }
        assert(!kernel_pages.empty());
    }

    const ADDRINT addr = INS_Address(ins);
    if (kernel_pages.count(getpage(addr)) == 1) {
        // Kernel instruction.
        if (INS_MemoryOperandCount(ins) > 0) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) CheckPinOps,
                           IARG_MEMORYOP_EA, 0,
                           IARG_CONTEXT,
                           IARG_UINT32, INS_Size(ins),
                           IARG_END);
        }
    } else {
        // Application instruction.

        // Print all PCs as they are executed.
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) TracePCs, IARG_INST_PTR, IARG_END);

        // Instrument system calls. Replace them with traps into gem5.
        if (INS_IsSyscall(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleSyscall,
                           IARG_CONTEXT,
                           IARG_ADDRINT, INS_Address(ins) + INS_Size(ins),
                           IARG_END);
            // Actually don't need to delete it since we're trapping into the kernel.
            // INS_Delete(ins);
        }
    }
}

static void
HandleContextChange(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, int32_t info, VOID *)
{
    log_ << "CLIENT: context change: reason=" << reason << "\n";
    if (reason == CONTEXT_CHANGE_REASON_FATALSIGNAL) {
        log_ << "CLIENT: signal number: " << info << "\n";
    }
}

static bool
InterceptSEGV(THREADID tid, int32_t sig, CONTEXT *ctx, bool has_handler, const EXCEPTION_INFO *info, void *)
{
    log_ << "CLIENT: Encountered SEGV: " << info->GetCodeAsString() << "\n";
    ADDRINT fault_addr;
    if (info->GetFaultyAccessAddress(&fault_addr)) {
        std::cerr << "CLIENT: SEGV at address 0x" << std::hex << fault_addr << "\n";
        std::cerr << "    at pc 0x" << info->GetExceptAddress() << "\n";
        // Save the user context.
        PIN_SaveContext(ctx, &user_ctx);

        // Swap in the kernel context.
        PIN_SaveContext(&saved_kernel_ctx, ctx);

        // Set the return value.
        RunResult result;
        result.result = RunResult::RUNRESULT_PAGEFAULT;
        result.addr = fault_addr;
        CopyOutRunResult(ctx, result);

        return false;
    }
    return true;
}

static void
usage(std::ostream &os)
{
    std::cerr << prog << ": gem5 pin CPU client\n";
    std::cerr << KNOB_BASE::StringKnobSummary() << "\n";
}

static void Fini(int32_t code, void *) {
    log_ << "Exiting: code = " << code << "\n";
    log_ << prog << ": Finished running the program, Pin exiting!\n";
    log_.close();
}

template <class T>
static int CheckPathArg(const T &arg) {
    const std::string &value = arg.Value();
    if (value.empty()) {
        std::cerr << "error: required option: " << arg.Name() << "\n";
        return -1;
    }
    OS_FILE_ATTRIBUTES attr;
    if (OS_GetFileAttributes(value.c_str(), &attr).generic_err != OS_RETURN_CODE_NO_ERROR) {
        std::cerr << "error: failed to open file: " << value << "\n";
        return -1;
    }
    return 0;
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

    if (CheckPathArg(req_path) < 0)
        return EXIT_FAILURE;
    if (CheckPathArg(resp_path) < 0)
        return EXIT_FAILURE;

    OS_FILE_ATTRIBUTES attr;
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

    // PIN_AddContextChangeFunction(HandleContextChange, nullptr);
    PIN_InterceptSignal(SIGSEGV, InterceptSEGV, nullptr);

    std::cerr << "runtime: starting program\n";

    PIN_StartProgram();
}
