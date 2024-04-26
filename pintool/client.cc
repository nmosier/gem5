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
static KNOB<bool> enable_inst_count(KNOB_MODE_WRITEONCE, "pintool", "inst_count", "1", "enable instruction counting");
static KNOB<bool> enable_trace(KNOB_MODE_WRITEONCE, "pintool", "trace", "0", "enable instruction tracing");
static std::unordered_set<ADDRINT> kernel_pages;
static ADDRINT virtual_vsyscall_base = 0;
static ADDRINT physical_vsyscall_base = 0;
static uint64_t inst_count = 0;

static ADDRINT getpage(ADDRINT addr) {
    return addr & ~(ADDRINT) 0xFFF;
}

static bool
IsKernelCode(ADDRINT pc)
{
    return kernel_pages.count(getpage(pc)) != 0;
}

static bool
IsKernelCode(INS ins)
{
    return IsKernelCode(INS_Address(ins));
}

static void
Abort()
{
    log_.close();
    PIN_ExitApplication(1);
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
        {"fs", REG_SEG_FS},
        {"fs_base", REG_SEG_FS_BASE},
        {"gs", REG_SEG_GS},
        {"gs_base", REG_SEG_GS_BASE},
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

          case PinOp::OP_GET_INSTCOUNT:
            PIN_SetContextReg(kernel_ctx_ptr, REG_RAX, inst_count);
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

          case PinOp::OP_SET_VSYSCALL_BASE:
            std::cerr << "CLIENT: SET_VSYSCALL_BASE\n";
            virtual_vsyscall_base = PIN_GetContextReg(kernel_ctx_ptr, REG_RDI);
            physical_vsyscall_base = PIN_GetContextReg(kernel_ctx_ptr, REG_RSI);
            PIN_ExecuteAt(kernel_ctx_ptr);

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
HandleSyscall(CONTEXT *ctx, ADDRINT pc)
{
    std::cerr << "CLIENT: handling syscall: 0x" << std::hex << pc << "\n";
    assert(!IsKernelCode(pc));
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
HandleCPUID(CONTEXT *ctx, ADDRINT next_pc)
{
    std::cerr << "CLIENT: handling cpuid: 0x" << std::hex << next_pc << "\n";

    // TODO: Share with HandleSyscall.
    assert(!IsKernelCode(next_pc));
    PIN_SaveContext(ctx, &user_ctx);
    PIN_SaveContext(&saved_kernel_ctx, ctx);

    // Update PC.
    PIN_SetContextReg(&user_ctx, REG_RIP, next_pc);

    // Run result is cpyid.
    RunResult result;
    result.result = RunResult::RUNRESULT_CPUID;
    CopyOutRunResult(ctx, result);
    PIN_ExecuteAt(ctx);
}

static ADDRINT
HandleFSGSAccess(ADDRINT effaddr)
{
    std::cerr << "Translating FS/GS access: 0x" << effaddr << "\n";
    return effaddr;
}

// TODO: Break this into mini-instrumentation functions.
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
    if (IsKernelCode(addr)) {
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

        // Instrument system calls. Replace them with traps into gem5.
        if (INS_IsSyscall(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleSyscall,
                           IARG_CONTEXT,
                           IARG_ADDRINT, INS_Address(ins) + INS_Size(ins),
                           IARG_END);
        }

        // Handle CPUIDs.
        if (INS_Opcode(ins) == XED_ICLASS_CPUID) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleCPUID,
                           IARG_CONTEXT,
                           IARG_ADDRINT, INS_Address(ins) + INS_Size(ins),
                           IARG_END);
        }

        // Accesses via the FS_BASE and GS_BASE registers are sensitive.
        for (uint32_t i = 0; i < INS_MemoryOperandCount(ins); ++i) {
            if (!(INS_MemoryOperandIsRead(ins, i) || INS_MemoryOperandIsWritten(ins, i)))
                continue;
            std::cerr << "checking instruction for FS/GS: " << INS_Disassemble(ins) << "\n";
            REG seg_reg = INS_OperandMemorySegmentReg(ins, INS_MemoryOperandIndexToOperandIndex(ins, i));
            if (!REG_valid(seg_reg))
                continue;
            REG seg_base_reg;
            switch (seg_reg) {
              case REG_SEG_FS:
                seg_base_reg = REG_SEG_FS_BASE;
                break;
              case REG_SEG_GS:
                seg_base_reg = REG_SEG_GS_BASE;
                break;
              default:
                std::cerr << "CLIENT: error: unexpected segment register: " << REG_StringShort(seg_reg) << "\n";
                std::abort();
            }
            std::cerr << "CLIENT: found sensitive FS/GS instruction: " << INS_Disassemble(ins) << "\n";
            // TODO: Shuold probably be predicated.
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleFSGSAccess,
                           IARG_MEMORYOP_EA, i,
                           IARG_RETURN_REGS, REG_INST_G0 + i,
                           IARG_CALL_ORDER, CALL_ORDER_LAST,
                           IARG_END);
            INS_RewriteMemoryOperand(ins, i, (REG) (REG_INST_G0 + i));
        }
    }
}

static ADDRINT
HandleVsyscallAccess(ADDRINT effaddr, ADDRINT effsize, ADDRINT next_pc, const CONTEXT *ctx)
{
    assert(virtual_vsyscall_base && physical_vsyscall_base);
    assert((virtual_vsyscall_base <= effaddr && effaddr + effsize <= virtual_vsyscall_base + 0x1000) ||
           effaddr + effsize <= virtual_vsyscall_base || virtual_vsyscall_base + 0x1000 <= effaddr);
    if (virtual_vsyscall_base <= effaddr && effaddr + effsize <= virtual_vsyscall_base + 0x1000) {
        const ADDRINT offset = effaddr - virtual_vsyscall_base;
        assert(physical_vsyscall_base);
        return physical_vsyscall_base + offset;
    } else {
        return effaddr;
    }
}


static std::unordered_set<ADDRINT> vsyscall_blacklist;

// Fixup vsyscalls.
static void
Instruction_Vsyscall(INS ins, void *)
{
    if (IsKernelCode(ins) || vsyscall_blacklist.count(INS_Address(ins)) == 0)
        return;

    std::cerr << "CLIENT: instrumenting instruction that has accessed vsyscall: 0x" << INS_Address(ins) << "\n";
    
    // FIXME: If we have a FS/GS access too this breaks.
    for (uint32_t i = 0; i < INS_MemoryOperandCount(ins); ++i) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleVsyscallAccess,
                                 IARG_MEMORYOP_EA, i,
                                 IARG_MEMORYOP_SIZE, i,
                                 IARG_ADDRINT, INS_Address(ins) + INS_Size(ins),
                                 IARG_CONST_CONTEXT,
                                 IARG_RETURN_REGS, REG_INST_G0 + i,
                                 IARG_CALL_ORDER, CALL_ORDER_LAST,
                                 IARG_END);
        INS_RewriteMemoryOperand(ins, i, (REG) (REG_INST_G0 + i));
    }
}

static void
HandleInstCount()
{
    ++inst_count;
}

static void
Instruction_InstCount(INS ins, void *)
{
    if (IsKernelCode(ins))
        return;
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleInstCount, IARG_END);
}

static void
HandleTrace(ADDRINT pc)
{
    std::cerr << "TRACE: 0x" << std::hex << pc << "\n";
}

static void
Instruction_Trace(INS ins, void *)
{
    if (IsKernelCode(ins))
        return;
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleTrace, IARG_INST_PTR, IARG_END);
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
    std::cerr << "CLIENT: Encountered SEGV: " << info->ToString() << "\n";

    ADDRINT fault_pc = info->GetExceptAddress();
    ADDRINT fault_addr;
    if (info->GetFaultyAccessAddress(&fault_addr)) {
        std::cerr << "CLIENT: SEGV at address 0x" << std::hex << fault_addr << "\n";
        std::cerr << "    at pc 0x" << fault_pc << "\n";

        RunResult result;
        
        // Was this a vsyscall access?
        // NOTE: The proper thing to do here if the virtual vsyscall base hasn't been set yet
        // is simply to deliver a page fault back to gem5.
        if (virtual_vsyscall_base &&
            virtual_vsyscall_base <= fault_addr &&
            fault_addr < virtual_vsyscall_base + 0x1000) {
            // Detected vsyscall access.
            // Trick Pin into re-instrumenting the instruction.
            std::cerr << "CLIENT: detected vsyscall access\n";
            vsyscall_blacklist.insert(fault_pc);
            PIN_RemoveInstrumentationInRange(fault_pc, fault_pc + 16); // TODO: Don't use magic 16 bytes.
            return false;
        } else {
            result.result = RunResult::RUNRESULT_PAGEFAULT;
            result.addr = fault_addr;
        }
        
        // Save the user context.
        PIN_SaveContext(ctx, &user_ctx);

        // Swap in the kernel context.
        PIN_SaveContext(&saved_kernel_ctx, ctx);

        // Set the return value.
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
    PIN_InitSymbols();
    
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

    // TODO: Reason better about ordering here.
    if (enable_trace.Value())
        INS_AddInstrumentFunction(Instruction_Trace, nullptr);
    INS_AddInstrumentFunction(Instruction_Vsyscall, nullptr);
    INS_AddInstrumentFunction(Instruction, nullptr);
    if (enable_inst_count.Value())
        INS_AddInstrumentFunction(Instruction_InstCount, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    PIN_InterceptSignal(SIGSEGV, InterceptSEGV, nullptr);

    std::cerr << "runtime: starting program\n";

    PIN_StartProgram();
}
