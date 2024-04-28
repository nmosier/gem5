#include <cstdlib>
#include <iostream>
#include <string>
#include <fstream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>

#include "pin.H"
#include "ops.hh"
#include "bbv.hh"
#include "ringbuf.hh"
#include "debug.hh"
#include "cpu/pin/regfile.h"

static const char *prog;
static KNOB<std::string> log_path(KNOB_MODE_WRITEONCE, "pintool", "log", "", "specify path to log file");
static std::ofstream log_;
static KNOB<std::string> req_path(KNOB_MODE_WRITEONCE, "pintool", "req_path", "", "specify path to CPU communciation FIFO");
static KNOB<std::string> resp_path(KNOB_MODE_WRITEONCE, "pintool", "resp_path", "", "specify path to response FIFO");
static KNOB<std::string> mem_path(KNOB_MODE_WRITEONCE, "pintool", "mem_path", "", "specify path to physmem file");
static KNOB<bool> enable_inst_count(KNOB_MODE_WRITEONCE, "pintool", "inst_count", "1", "enable instruction counting");
static KNOB<bool> enable_trace(KNOB_MODE_WRITEONCE, "pintool", "trace", "0", "enable instruction tracing");
static KNOB<std::string> bbv_path(KNOB_MODE_WRITEONCE, "pintool", "bbv_path", "", "BBV output path (empty string to disable)");
static KNOB<uint64_t> bbv_interval(KNOB_MODE_WRITEONCE, "pintool", "bbv_interval", "0", "BBV interval size, in instructions");

static CONTEXT user_ctx;
static CONTEXT saved_kernel_ctx;
static std::unordered_set<ADDRINT> kernel_pages;
static ADDRINT virtual_vsyscall_base = 0;
static ADDRINT physical_vsyscall_base = 0;
static uint64_t inst_count = 0;
static BBVTrace bbv_trace;

constexpr bool enable_pc_hist = false;

static uint64_t pinops_count = 0;

static bool
enable_bbv()
{
    return !bbv_path.Value().empty();
}

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

static bool
IsKernelCode(TRACE trace)
{
    return IsKernelCode(TRACE_Address(trace));
}

[[noreturn]] static void
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
	// {"cr4", REG_CR4},
	{"fcw", REG_FPCW},
	{"fsw", REG_FPSW},
	{"ftag", REG_FPTAG},

	// Float regs
#if 0
	{"mm0", REG_MM0},
	{"mm1", REG_MM1},
	{"mm2", REG_MM2},
	{"mm3", REG_MM3},
	{"mm4", REG_MM4},
	{"mm5", REG_MM5},
	{"mm6", REG_MM6},
	{"mm7", REG_MM7},
#endif
	{"st0", REG_ST0},
	{"st1", REG_ST1},
	{"st2", REG_ST2},
	{"st3", REG_ST3},
	{"st4", REG_ST4},
	{"st5", REG_ST5},
	{"st6", REG_ST6},
	{"st7", REG_ST7},
	{"xmm0", REG_XMM0},
	{"xmm1", REG_XMM1},
	{"xmm2", REG_XMM2},
	{"xmm3", REG_XMM3},
	{"xmm4", REG_XMM4},
	{"xmm5", REG_XMM5},
	{"xmm6", REG_XMM6},
	{"xmm7", REG_XMM7},
        {"xmm8", REG_XMM8},
        {"xmm9", REG_XMM9},
        {"xmm10", REG_XMM10},
        {"xmm11", REG_XMM11},
        {"xmm12", REG_XMM12},
        {"xmm13", REG_XMM13},
        {"xmm14", REG_XMM14},
        {"xmm15", REG_XMM15},
    };

    const auto it = name_to_reg.find(name);
    if (it == name_to_reg.end()) {
        std::cerr << "error: failed to translate \"" << name << "\" to Pin REG\n";
        Abort();
    }
    return it->second;
}

static void
FixupRegvalFromGem5(REG reg, std::vector<uint8_t> &data)
{
    switch (reg) {
      case REG_FPCW: // 2->8
      case REG_FPSW:
      case REG_FPTAG:
        assert(data.size() == 2);
        data.resize(8, 0);
        break;


      default:
        break;
    }
}

static void
FixupRegvalToGem5(REG reg, std::vector<uint8_t> &data)
{
    switch (reg) {
      case REG_FPCW: // 8->2
      case REG_FPSW:
      case REG_FPTAG:
        assert(data.size() == 8);
        assert(std::count(data.begin() + 2, data.begin() + 8, 0) == 6);
        data.resize(2);
        break;

      default:
        break;
    }
}

static ADDRINT
CheckPinOps(ADDRINT effaddr, const CONTEXT *kernel_ctx_ptr, ADDRINT next_pc)
{
    if (!is_pinop_addr((void *) effaddr)) {
        std::cerr << "warn: inconsistent pinop at pc 0x" << std::hex << PIN_GetContextReg(kernel_ctx_ptr, REG_RIP) << "\n";
        return PIN_GetContextReg(kernel_ctx_ptr, REG_RAX);
    }

    dbgs() << "CLIENT: handling pinop (next pc: 0x" << next_pc << ")\n";

    ++pinops_count;
    
    // Don't save kernel context by default. But do skip over PinOp.
    // PIN_SetContextReg(kernel_ctx_ptr, REG_RIP, next_pc);

    PinOp op = (PinOp) (effaddr - (uintptr_t) pinops_addr_base);
    switch (op) {
      case PinOp::OP_RESETUSER:
        PIN_SaveContext(kernel_ctx_ptr, &user_ctx);
        return 0;

      case PinOp::OP_GET_INSTCOUNT:
        return inst_count;
            
      case PinOp::OP_SET_REG:
        {
            dbgs() << "CLIENT: handling SET_REG\n";
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
#if 0
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
#endif

            FixupRegvalFromGem5(reg, buf);

            assert(buf.size() == REG_Size(reg));
            PIN_SetContextRegval(&user_ctx, reg, buf.data());
            // PIN_ExecuteAt(kernel_ctx_ptr);
        }
        return 0;

      case PinOp::OP_GET_REG:
        {
            dbgs() << "CLIENT: handling GET_REG\n";
            const std::string regname = CopyUserString(PIN_GetContextReg(kernel_ctx_ptr, REG_RDI));
            const REG reg = ParseReg(regname);
            const ADDRINT user_data = PIN_GetContextReg(kernel_ctx_ptr, REG_RSI);
            const uint8_t user_size = PIN_GetContextReg(kernel_ctx_ptr, REG_RDX);
            std::vector<uint8_t> buf(user_size);
            assert(buf.size() == REG_Size(reg));
            PIN_GetContextRegval(&user_ctx, reg, buf.data());
            FixupRegvalToGem5(reg, buf);
            if (PIN_SafeCopy((void *) user_data, buf.data(), buf.size()) != buf.size()) {
                std::cerr << "error: failed to copy register data to kernel\n";
                Abort();
            }
#if 0
            if (buf.size() == 8) {
                std::cerr << "CLIENT: GET_REG " << regname << " <- " << std::hex << "0x" << (*(const uint64_t *)buf.data()) << "\n";
            }
#endif
            // PIN_ExecuteAt(kernel_ctx_ptr);
        };
        // TODO: Consider returning register size?
        return 0;
            

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
                std::cerr << "PinOp GET_CPUPATH: CPU path does not fit in kernel buffer (" << kernel_size << " bytes)\n";
                Abort();
            }
            if (PIN_SafeCopy((void *) kernel_data, path.data(), path.size()) != path.size()) {
                std::cerr << "PinOp GET_CPUPATH: failed to copy\n";
                Abort();
            }
            dbgs() << "CLIENT: Serived GET_CPUPATH\n";
        }
        return 0;

      case PinOp::OP_SET_VSYSCALL_BASE:
        dbgs() << "CLIENT: SET_VSYSCALL_BASE\n";
        virtual_vsyscall_base = PIN_GetContextReg(kernel_ctx_ptr, REG_RDI);
        physical_vsyscall_base = PIN_GetContextReg(kernel_ctx_ptr, REG_RSI);
        return 0;

      case PinOp::OP_EXIT:
        dbgs() << "Got EXIT\n";
        PIN_ExitApplication(0);
        std::abort(); // UNREACHABLE

      case PinOp::OP_ABORT:
        dbgs() << "Got ABORT\n";
        PIN_ExitApplication(1);
        std::abort(); // UNREACHABLE

      case PinOp::OP_RUN:
        PIN_SaveContext(kernel_ctx_ptr, &saved_kernel_ctx);
        PIN_SetContextReg(&saved_kernel_ctx, REG_RIP, next_pc);
        PIN_ExecuteAt(&user_ctx);
        std::abort(); // TODO: UNREACHABLE

      default:
        std::cerr << "invalid pinop: " << (int) op << "\n";
        Abort();
    }
}


static void
HandleSyscall(CONTEXT *ctx, ADDRINT pc)
{
    dbgs() << "CLIENT: handling syscall: 0x" << std::hex << pc << ": number=" << std::dec << PIN_GetContextReg(ctx, REG_RAX) << "\n";
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
    dbgs() << "CLIENT: handling cpuid: 0x" << std::hex << next_pc << "\n";

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
    dbgs() << "Translating FS/GS access: 0x" << effaddr << "\n";
    return effaddr;
}

static std::unordered_map<ADDRINT, PinOp> pinops_blacklist;


static void
HandleOp_RESETUSER(const CONTEXT *kernel_ctx)
{
    PIN_SaveContext(kernel_ctx, &user_ctx);
}

static ADDRINT
HandleOp_GET_INSTCOUNT()
{
    return inst_count;
}

static void
HandleOp_SET_REG(const char *user_name_ptr, const uint8_t *user_data_ptr, size_t size)
{
    const std::string regname = CopyUserString((ADDRINT) user_name_ptr);
    const REG reg = ParseReg(regname);
    std::vector<uint8_t> buf(size);
    if (PIN_SafeCopy(buf.data(), user_data_ptr, buf.size()) != buf.size()) {
        std::cerr << "CLIENT: error: failed to copy register data\n";
        Abort();
    }
    // TODO: Should offload this to gem5 entirely.
    FixupRegvalFromGem5(reg, buf);
    assert(buf.size() == REG_Size(reg));
    PIN_SetContextRegval(&user_ctx, reg, buf.data());
}

static void
HandleOp_GET_REG(const char *user_name_ptr, uint8_t *user_data_ptr, size_t size)
{
    const std::string regname = CopyUserString((ADDRINT) user_name_ptr);
    const REG reg = ParseReg(regname);
    std::vector<uint8_t> buf(size);
    assert(buf.size() == REG_Size(reg));
    PIN_GetContextRegval(&user_ctx, reg, buf.data());
    FixupRegvalToGem5(reg, buf);
    if (PIN_SafeCopy((void *) user_data_ptr, buf.data(), buf.size()) != buf.size()) {
        std::cerr << "error: failed to copy register data to kernel\n";
        Abort();
    }
}

static void
HandleOp_GetPath(const char *user_ptr, size_t size, std::string path)
{
    path.push_back('\0');
    if (path.size() > size) {
        std::cerr << "CLIENT: path too large to fit in kernel buffer: " << path << "\n";
        Abort();
    }
    if (PIN_SafeCopy((void *) user_ptr, path.data(), path.size()) != path.size()) {
        std::cerr << "CLIENT: error: failed to copy\n";
        Abort();
    }
}

static void
HandleOp_GET_REQPATH(const char *user_ptr, size_t size)
{
    HandleOp_GetPath(user_ptr, size, req_path.Value());
}

static void
HandleOp_GET_RESPPATH(const char *user_ptr, size_t size)
{
    HandleOp_GetPath(user_ptr, size, resp_path.Value());
}

static void
HandleOp_GET_MEMPATH(const char *user_ptr, size_t size)
{
    HandleOp_GetPath(user_ptr, size, mem_path.Value());
}

static void
HandleOp_SET_VSYSCALL_BASE(void *virt, void *phys)
{
    virtual_vsyscall_base = (ADDRINT) virt;
    physical_vsyscall_base = (ADDRINT) phys;
}

[[noreturn]] static void
HandleOp_EXIT(int32_t code)
{
    std::cerr << "Exiting " << std::dec << code << "\n";
    PIN_ExitApplication(code);
    std::abort(); // TODO: Unreachable
}

[[noreturn]] static void
HandleOp_ABORT()
{
    std::cerr << "Aborting\n";
    PIN_ExitApplication(1);
    std::abort(); // TODO: Unreachable.
}

static void
HandleOp_RUN(const CONTEXT *kernel_ctx_ptr, ADDRINT next_pc)
{
    PIN_SaveContext(kernel_ctx_ptr, &saved_kernel_ctx);
    PIN_SetContextReg(&saved_kernel_ctx, REG_RIP, next_pc);
    PIN_ExecuteAt(&user_ctx);
    std::abort(); // TODO: UNREACHABLE    
}

static void
HandleOp_SET_REGS(const PinRegFile *user_regfile_ptr)
{
    PinRegFile rf;
    if (PIN_SafeCopy(&rf, user_regfile_ptr, sizeof rf) != sizeof rf) {
        std::cerr << "CLIENT: Failed to copy regfile\n";
        Abort();
    }
    const auto set_reg = [] (REG reg, uint64_t value) {
        PIN_SetContextReg(&user_ctx, reg, value);
    };
    
    // Set integer registers.
    set_reg(REG_RAX, rf.rax);
    set_reg(REG_RBX, rf.rbx);
    set_reg(REG_RCX, rf.rcx);
    set_reg(REG_RDX, rf.rdx);
    set_reg(REG_RDI, rf.rdi);
    set_reg(REG_RSI, rf.rsi);
    set_reg(REG_RSP, rf.rsp);
    set_reg(REG_RBP, rf.rbp);
    set_reg(REG_R8, rf.r8);
    set_reg(REG_R9, rf.r9);
    set_reg(REG_R10, rf.r10);
    set_reg(REG_R11, rf.r11);
    set_reg(REG_R12, rf.r12);
    set_reg(REG_R13, rf.r13);
    set_reg(REG_R14, rf.r14);
    set_reg(REG_R15, rf.r15);
    set_reg(REG_RIP, rf.rip);

    // Set floating-point registers.
    for (int i = 0; i < 8; ++i)
        PIN_SetContextRegval(&user_ctx, REG(REG_ST0 + i), (const uint8_t *) &rf.fprs[i]);
    for (int i = 0; i < 16; ++i)
        PIN_SetContextRegval(&user_ctx, REG(REG_XMM0 + i), (const uint8_t *) &rf.xmms[i]);
    set_reg(REG_FPCW, rf.fcw);
    set_reg(REG_FPSW, rf.fsw);
    set_reg(REG_FPTAG, rf.ftag);

    // Misc regs.
    set_reg(REG_SEG_FS, rf.fs);
    set_reg(REG_SEG_GS, rf.gs);
    set_reg(REG_SEG_FS_BASE, rf.fs_base);
    set_reg(REG_SEG_GS_BASE, rf.gs_base);

    dbgs() << "DEBUG: setting REG_SEG_FS_BASE to 0x" << std::hex << rf.fs_base << "\n";
}

static void
HandleOp_GET_REGS(PinRegFile *user_regfile_ptr)
{
    PinRegFile rf;
    std::memset(&rf, 0, sizeof rf);

    const auto get_reg = [] (REG reg, auto &value) {
        value = PIN_GetContextReg(&user_ctx, reg);
    };

    // Get integer registers.
    get_reg(REG_RAX, rf.rax);
    get_reg(REG_RBX, rf.rbx);
    get_reg(REG_RCX, rf.rcx);
    get_reg(REG_RDX, rf.rdx);
    get_reg(REG_RDI, rf.rdi);
    get_reg(REG_RSI, rf.rsi);
    get_reg(REG_RSP, rf.rsp);
    get_reg(REG_RBP, rf.rbp);
    get_reg(REG_R8, rf.r8);
    get_reg(REG_R9, rf.r9);
    get_reg(REG_R10, rf.r10);
    get_reg(REG_R11, rf.r11);
    get_reg(REG_R12, rf.r12);
    get_reg(REG_R13, rf.r13);
    get_reg(REG_R14, rf.r14);
    get_reg(REG_R15, rf.r15);
    get_reg(REG_RIP, rf.rip);

    // Get floating-point registers.
    for (int i = 0; i < 8; ++i)
        PIN_GetContextRegval(&user_ctx, REG(REG_ST0 + i), (uint8_t *) &rf.fprs[i]);
    for (int i = 0; i < 16; ++i)
        PIN_GetContextRegval(&user_ctx, REG(REG_XMM0 + i), (uint8_t *) &rf.xmms[i]);
    get_reg(REG_FPCW, rf.fcw);
    get_reg(REG_FPSW, rf.fsw);
    get_reg(REG_FPTAG, rf.ftag);

    // Misc regs.
    get_reg(REG_SEG_FS, rf.fs);
    get_reg(REG_SEG_GS, rf.gs);
    get_reg(REG_SEG_FS_BASE, rf.fs_base);
    get_reg(REG_SEG_GS_BASE, rf.gs_base);

    // Copy out.
    if (PIN_SafeCopy(user_regfile_ptr, &rf, sizeof rf) != sizeof rf) {
        std::cerr << "CLIENT: failed to copy regfile\n";
        Abort();
    }

    dbgs() << "DEBUG: getting FS_BASE: 0x" << std::hex << rf.fs_base << "\n";
}

static void
Instrument_Instruction_PinOps(INS ins, void *)
{
    const ADDRINT pc = INS_Address(ins);
    const auto it = pinops_blacklist.find(pc);
    if (it == pinops_blacklist.end())
        return;

    const PinOp op = it->second;

    dbgs() << "CLIENT: instrumenting pinop instruction: 0x" << INS_Address(ins) << ": op=" << std::dec << op << "\n";

    assert(INS_MemoryOperandCount(ins) == 1);

    switch (op) {
      case PinOp::OP_RESETUSER:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_RESETUSER,
                                 IARG_CONST_CONTEXT,
                                 IARG_END);
        break;

      case PinOp::OP_GET_INSTCOUNT:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_GET_INSTCOUNT,
                                 IARG_RETURN_REGS, REG_RAX,
                                 IARG_END);
        break;

      case PinOp::OP_SET_REG:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_SET_REG,
                                 IARG_REG_VALUE, REG_RDI,
                                 IARG_REG_VALUE, REG_RSI,
                                 IARG_REG_VALUE, REG_RDX,
                                 IARG_END);
        break;

      case PinOp::OP_GET_REG:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_GET_REG,
                                 IARG_REG_VALUE, REG_RDI,
                                 IARG_REG_VALUE, REG_RSI,
                                 IARG_REG_VALUE, REG_RDX,
                                 IARG_END);
        break;

      case PinOp::OP_GET_REQPATH:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_GET_REQPATH,
                                 IARG_REG_VALUE, REG_RDI,
                                 IARG_REG_VALUE, REG_RSI,
                                 IARG_END);
        break;

      case PinOp::OP_GET_RESPPATH:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_GET_RESPPATH,
                                 IARG_REG_VALUE, REG_RDI,
                                 IARG_REG_VALUE, REG_RSI,
                                 IARG_END);
        break;

      case PinOp::OP_GET_MEMPATH:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_GET_MEMPATH,
                                 IARG_REG_VALUE, REG_RDI,
                                 IARG_REG_VALUE, REG_RSI,
                                 IARG_END);
        break;

      case PinOp::OP_SET_VSYSCALL_BASE:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_SET_VSYSCALL_BASE,
                                 IARG_REG_VALUE, REG_RDI,
                                 IARG_REG_VALUE, REG_RSI,
                                 IARG_END);
        break;

      case PinOp::OP_EXIT:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_EXIT,
                                 IARG_REG_VALUE, REG_RDI,
                                 IARG_END);
        break;

      case PinOp::OP_ABORT:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_ABORT,
                                 IARG_END);
        break;

      case PinOp::OP_RUN:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_RUN,
                                 IARG_CONST_CONTEXT,
                                 IARG_ADDRINT, pc + INS_Size(ins),
                                 IARG_END);
        break;

      case PinOp::OP_SET_REGS:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_SET_REGS,
                                 IARG_REG_VALUE, REG_RDI,
                                 IARG_END);
        break;

      case PinOp::OP_GET_REGS:
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleOp_GET_REGS,
                                 IARG_REG_VALUE, REG_RDI,
                                 IARG_END);
        break;

      default:
        std::cerr << "CLIENT: fatal: unimplemented pinop " << std::dec << op << "\n";
        Abort();
    }

    INS_Delete(ins);
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
    if (IsKernelCode(addr))
        return;

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
        dbgs() << "CLIENT: checking instruction for FS/GS: " << INS_Disassemble(ins) << "\n";
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
        dbgs() << "CLIENT: found sensitive FS/GS instruction: 0x" << INS_Address(ins) << ": " << INS_Disassemble(ins) << "\n";
        // TODO: Shuold probably be predicated.
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleFSGSAccess,
                       IARG_MEMORYOP_EA, i,
                       IARG_RETURN_REGS, REG_INST_G0 + i,
                       IARG_CALL_ORDER, CALL_ORDER_LAST,
                       IARG_END);
        INS_RewriteMemoryOperand(ins, i, (REG) (REG_INST_G0 + i));
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

    dbgs() << "CLIENT: instrumenting instruction that has accessed vsyscall: 0x" << INS_Address(ins) << "\n";
    
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
HandleInstCount(ADDRINT num_insts)
{
    inst_count += num_insts;
}

static void
Instrument_Trace_InstCount(TRACE trace, void *)
{
    if (IsKernelCode(trace))
        return;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR) HandleInstCount,
                       IARG_ADDRINT, BBL_NumIns(bbl),
                       IARG_END);
    }
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
Handle_Trace_BBV(BBVBlock *block)
{
    block->increment();
}


static void
Instrument_Trace_BBV(TRACE trace, void *)
{
    if (IsKernelCode(trace))
        return;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        BBVBlock *block = bbv_trace.block(BBL_Address(bbl));
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR) Handle_Trace_BBV,
                       IARG_PTR, block,
                       IARG_END);
    }
}

static RingBuffer<ADDRINT, 16> pc_hist(0);

static void
Handle_Trace_Hist(ADDRINT pc)
{
    pc_hist.push(pc);
}

static void
Instrument_Trace_Hist(TRACE trace, void *)
{
    if (IsKernelCode(trace))
        return;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR) Handle_Trace_Hist,
                       IARG_INST_PTR,
                       IARG_END);
    }
}

static void
DumpHistory()
{
    std::vector<ADDRINT> hist;
    pc_hist.get(std::back_inserter(hist));
    std::cerr << "history:";
    for (ADDRINT pc : hist)
        std::cerr << " 0x" << std::hex << pc;
    std::cerr << "\n";
}

static void
PrintCall(void *s, int c, size_t n)
{
    std::cerr << "TRACE: memset(" << s << ", " << c << ", " << n << ")\n";
    DumpHistory();
}

static void
Instrument_Instruction_PrintCall(INS ins, void *)
{
    if (INS_Address(ins) == 0x46ab40) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) PrintCall,
                       IARG_REG_VALUE, REG_RDI,
                       IARG_REG_VALUE, REG_ESI,
                       IARG_REG_VALUE, REG_RDX,
                       IARG_END);
    }
}


static bool
InterceptSEGV(THREADID tid, int32_t sig, CONTEXT *ctx, bool has_handler, const EXCEPTION_INFO *info, void *)
{
    std::cerr << "CLIENT: Encountered SEGV: " << info->ToString() << "\n";

    const auto code = PIN_GetExceptionCode(info);
    const auto ex_class = PIN_GetExceptionClass(code);
    if (ex_class != EXCEPTCLASS_ACCESS_FAULT) {
        std::cerr << "CLIENT: unexpected exception class (" << ex_class << ")\n";
        return true;
    }

    // Print FS
    std::cerr << "FS_BASE: 0x" << std::hex << PIN_GetContextReg(ctx, REG_SEG_FS_BASE) << "\n";

    assert(info->IsAccessFault());

    ADDRINT fault_pc = info->GetExceptAddress();
    ADDRINT fault_addr;
    [[maybe_unused]] const bool fault_addr_result = info->GetFaultyAccessAddress(&fault_addr);
    assert(fault_addr_result);
    
    std::cerr << "CLIENT: SEGV at address 0x" << std::hex << fault_addr << "\n";
    std::cerr << "    at pc 0x" << fault_pc << "\n";

    if (fault_addr == 0) {
        std::cerr << "CLIENT: null pointer dereference; aborting\n";
        DumpHistory();
        return true;
    }

    // Was this segfault in kernel code?
    if (IsKernelCode(fault_pc)) {
        // If this is a pinop fault, then we just need to reinstrument it and add it to the pinop
        // instruction list.
        if (is_pinop_addr((void *) fault_addr)) {
            std::cerr << "CLIENT: detected new pinop instruction: 0x" << fault_pc << "\n";
            pinops_blacklist[fault_pc] = static_cast<PinOp>(fault_addr - pinops_addr_base);
            PIN_RemoveInstrumentationInRange(fault_pc, fault_pc + 16); // TODO: Don't use magic 16 bytes.
            return false;
        }

        // Otherwise, we have an unknown kernel fault.
        std::cerr << "CLIENT: kernel faulted, aborting\n";
        return true;
    }

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

static void
usage(std::ostream &os)
{
    std::cerr << prog << ": gem5 pin CPU client\n";
    std::cerr << KNOB_BASE::StringKnobSummary() << "\n";
}

static void Fini(int32_t code, void *) {
    std::cerr << "Exiting: code = " << code << "\n";
    std::cerr << prog << ": Finished running the program, Pin exiting!\n";
    std::cerr << "STATS: total pinops: " << std::dec << pinops_count << "\n";
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
#if 0
    PIN_InitSymbols();
#endif
    
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
    // INS_AddInstrumentFunction(Instrument_Instruction_PrintCall, nullptr);
    if constexpr (enable_pc_hist)
        TRACE_AddInstrumentFunction(Instrument_Trace_Hist, nullptr);
    if (enable_trace.Value())
        INS_AddInstrumentFunction(Instruction_Trace, nullptr);
    INS_AddInstrumentFunction(Instruction_Vsyscall, nullptr);
    if (enable_inst_count.Value())
        TRACE_AddInstrumentFunction(Instrument_Trace_InstCount, nullptr);
    if (enable_bbv()) {
        TRACE_AddInstrumentFunction(Instrument_Trace_BBV, nullptr);
    }
    INS_AddInstrumentFunction(Instruction, nullptr);
    INS_AddInstrumentFunction(Instrument_Instruction_PinOps, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    PIN_InterceptSignal(SIGSEGV, InterceptSEGV, nullptr);

    std::cerr << "runtime: starting program\n";

    PIN_StartProgram();
}
