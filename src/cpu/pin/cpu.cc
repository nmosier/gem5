#include "cpu/pin/cpu.hh"

#include <cstdlib>
#include <fcntl.h>
#include <sys/wait.h>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/times.h>

#include "cpu/simple_thread.hh"
#include "params/BasePinCPU.hh"
#include "cpu/pin/message.hh"
#include "debug/Pin.hh"
#include "sim/system.hh"
#include "arch/x86/regs/int.hh"
#include "arch/x86/cpuid.hh"
#include "arch/x86/isa.hh"
#include "sim/faults.hh"
#include "arch/x86/utility.hh"

namespace gem5
{

namespace pin
{

CPU::CPU(const BasePinCPUParams &params)
    : BaseCPU(params),
      tickEvent([this] { tick(); }, "BasePinCPU tick", false, Event::CPU_Tick_Pri),
      _status(Idle),
      dataPort(name() + ".dcache_port", this),
      instPort(name() + ".icache_port", this),
      pinPid(-1),
      system(params.system),
      traceInsts(params.traceInsts),
      enableBBV(params.enableBBV),
      interval(params.interval)
{
    thread = std::make_unique<SimpleThread>(
        this, /*thread_num*/0, params.system,
        params.workload[0], params.mmu,
        params.isa[0], params.decoder[0]);
    thread->setStatus(ThreadContext::Halted);
    tc = thread->getTC();
    threadContexts.push_back(tc);

    if (params.countInsts)
        ctrInsts = 0;
}

void
CPU::haltContext()
{
    DPRINTF(Pin, "Halting Pin process\n");
    // Tell Pin to exit.
    assert(pinPid >= 0 && reqFd >= 0 && respFd >= 0);

    Message msg;
    msg.type = Message::Exit;
    msg.send(reqFd);
    
    close(reqFd);
    close(respFd);

    if (waitpid(pinPid, nullptr, 0) < 0)
        panic("waitpid failed!\n");

    // Dump times.
    struct tms tms;
    if (times(&tms) < 0)
        panic("times(2) failed\n");
    const auto tick = sysconf(_SC_CLK_TCK);
    DPRINTF(Pin, "user.pin: %fs, sys.pin: %fs, user.gem5: %fs, sys.gem5: %fs\n", 
            static_cast<double>(tms.tms_cutime) / tick,
            static_cast<double>(tms.tms_cstime) / tick,
	    static_cast<double>(tms.tms_utime) / tick,
	    static_cast<double>(tms.tms_stime) / tick);
}

bool
CPU::PinRequestPort::recvTimingResp(PacketPtr pkt)
{
    fatal("Unsupported: %s", __func__);
}

void
CPU::PinRequestPort::recvReqRetry()
{
    fatal("Unsupported: %s", __func__);
}

Port &
CPU::getDataPort()
{
    return dataPort;
}

Port &
CPU::getInstPort()
{
    return instPort;
}

void
CPU::wakeup(ThreadID tid)
{
    fatal("Unsupported: %s", __func__);
}

Counter
CPU::totalInsts() const
{
    return ctrInsts ? *ctrInsts : 0;
}

Counter
CPU::totalOps() const
{
    warn_once("Pretending totalInsts == totalOps\n");
    return totalInsts();
}

CPU *getCPU(const BasePinCPUParams &params) {
    return new CPU(params);
}

const char *
CPU::getPinRoot()
{
    const char *pin_root = std::getenv("PIN_ROOT");
    fatal_if(pin_root == nullptr, "environment variable PIN_ROOT not set!"); // TODO: Move this to build variable?
    return pin_root;
}

std::string
CPU::getPinExe()
{
    return std::string(getPinRoot()) + "/pin";
}

const char *
CPU::getPinTool()
{
    const char *pin_tool = std::getenv("PIN_TOOL");
    fatal_if(pin_tool == nullptr, "environment variable PIN_TOOL not set!");
    return pin_tool;
}

const char *
CPU::getRequestPath()
{
    const char *req_path = std::getenv("PIN_REQ");
    fatal_if(req_path == nullptr, "environment variable PIN_REQ not set!");
    return req_path;
}

const char *
CPU::getResponsePath()
{
    const char *resp_path = std::getenv("PIN_RESP");
    fatal_if(resp_path == nullptr, "environment variable PIN_RESP not set!");
    return resp_path;
}

std::string
CPU::getDummyProg()
{
    const char *kernel_path = std::getenv("PIN_KERNEL");
    fatal_if(kernel_path == nullptr, "environment variable PIN_KERNEL not set!");
    return kernel_path;
}

void
CPU::init()
{
    BaseCPU::init();
    fatal_if(numThreads != 1, "Pin: Multithreading not supported");
    warn("Pin::CPU::init not complete\n");
}

void
CPU::startup()
{
    BaseCPU::startup();

    // TODO: Remove this crap. unused i think.
    tc->simcall_info.type = ThreadContext::SimcallInfo::INVALID; // TODO: This is definitely not the appropriate place for this.

    // Create pipes for bidirectional communication.
    int req_fds[2];
    if (pipe(req_fds) < 0)
        fatal("pipe failed: %s", std::strerror(errno));
    int resp_fds[2];
    if (pipe(resp_fds) < 0)
        fatal("pipe failed: %s", std::strerror(errno));
    reqFd = req_fds[1];
    respFd = resp_fds[0];
    const int remote_req_fd = req_fds[0];
    const int remote_resp_fd = resp_fds[1];

    // TODO: Pass fd's directly to Pintool?
    char req_path[32];
    std::sprintf(req_path, "/dev/fd/%d", remote_req_fd);
    char resp_path[32];
    std::sprintf(resp_path, "/dev/fd/%d", remote_resp_fd);
    const std::string pin_tool = getPinTool();
    const std::string pin_exe = getPinExe();
    const std::string dummy_prog = getDummyProg();

    std::stringstream shm_path_ss;
    const auto &backing_store = system->getPhysMem().getBackingStore();
    fatal_if(backing_store.size() != 1, "Pin CPU supports only one backing store entry");
    const int shm_fd = backing_store[0].shmFd;
    fatal_if(shm_fd < 0, "Pin CPU requires shared memory backing store");
    shm_path_ss << "/dev/fd/" << shm_fd;
    const std::string shm_path = shm_path_ss.str();

    int shm_fd_flags;
    if ((shm_fd_flags = fcntl(shm_fd, F_GETFD)) < 0)
        fatal("fcntl FD_GETFD failed");
    shm_fd_flags &= ~FD_CLOEXEC;
    if (fcntl(shm_fd, F_SETFD, shm_fd_flags) < 0)
        fatal("fcntl FD_SETFD failed");

    pinPid = fork();
    if (pinPid < 0) {
        fatal("fork: %s", std::strerror(errno));
    } else if (pinPid == 0) {
        // Create log file for this fucking mess.
        // It will be for the kernel.
        const int kernout_fd = open("kernout.txt", O_WRONLY | O_APPEND | O_TRUNC | O_CREAT, 0664);
        if (kernout_fd < 0)
            panic("Failed to create kernel.log\n");
        if (dup2(kernout_fd, STDOUT_FILENO) < 0)
            panic("dup2 failed\n");

        const int kernerr_fd = open("kernerr.txt", O_WRONLY | O_APPEND | O_TRUNC | O_CREAT, 0664);
        if (kernerr_fd < 0)
            panic("Failed to create kernerr.txt");
        if (dup2(kernerr_fd, STDERR_FILENO) < 0)
            panic("dup2 failed\n");

        
        // This is the Pin subprocess. Execute pin.
        std::vector<std::string> args;
        auto it = std::back_inserter(args);

	// Pin executable.
        *it++ = pin_exe;

        // Pin args.
        if (std::getenv("PIN_APPDEBUG")) {
            *it++ = "-appdebug"; *it++ = "1";
        }
        if (std::getenv("PIN_TOOLDEBUG")) {
            *it++ = "-pause_tool"; *it++ = "30";
        }

        // Pintool.
        *it++ = "-t"; *it++ = pin_tool;

        // Pintool args.
        *it++ = "-log"; *it++ = "pin.log";
        *it++ = "-req_path"; *it++ = req_path;
        *it++ = "-resp_path"; *it++ = resp_path;
        *it++ = "-mem_path"; *it++ = shm_path;
        *it++ = "-inst_count"; *it++ = ctrInsts ? "1" : "0";
        *it++ = "-trace", *it++ = traceInsts ? "1" : "0";

        // Workload.
        *it++ = "--";
        *it++ = dummy_prog;

        std::vector<char *> args_c;
        for (const std::string &s : args)
            args_c.push_back(const_cast<char *>(s.c_str()));
        args_c.push_back(nullptr);

	std::stringstream cmd_ss;
	for (const std::string &arg : args)
	  cmd_ss << arg << " ";
	DPRINTF(Pin, "Starting Pin: %s\n", cmd_ss.str());

        execvp(args_c[0], args_c.data());
        fatal("execvp failed: %s", std::strerror(errno));
    }

    // Close the remote end of the socket; it will remain open in the Pin subprocess.
    close(req_fds[0]); // Close read-end of request pipe.
    close(resp_fds[1]); // Close write-end of response pipe.
    
    // Send initial ACK.
    Message msg;
    msg.type = Message::Ack;
    DPRINTF(Pin, "Sending initial ACK\n");
    msg.send(reqFd);
    DPRINTF(Pin, "Receiving initial ACK\n");
    msg.recv(respFd);
    panic_if(msg.type != Message::Ack, "Received message other than ACK at pintool startup!\n");
    DPRINTF(Pin, "received ACK from pintool\n");

    // Copy over initial state.
    syncStateToPin(true);
}

void
CPU::activateContext(ThreadID tid)
{
    assert(tid == 0);
    assert(thread);

    schedule(tickEvent, clockEdge(Cycles(0)));
    _status = Running;
}

void
CPU::tick()
{
    Tick delay = 0;

    assert(_status != Idle);
    assert(_status == Running);

    pinRun(); // TODO: Will need to communicate how many ticks required.

    if (tc->status() == ThreadContext::Halting ||
        tc->status() == ThreadContext::Halted) {
        haltContext();
    }
    
    ++delay; // FIXME

    if (_status != Idle) {
        schedule(tickEvent, clockEdge(ticksToCycles(delay)));
    }
}

  // TODO: Can rewrite this without using macros. 
#define FOREACH_IREG() \
    do { \
        APPLY_IREG(rax, X86ISA::int_reg::Rax); \
        APPLY_IREG(rbx, X86ISA::int_reg::Rbx); \
        APPLY_IREG(rcx, X86ISA::int_reg::Rcx); \
        APPLY_IREG(rdx, X86ISA::int_reg::Rdx); \
        APPLY_IREG(rsi, X86ISA::int_reg::Rsi); \
        APPLY_IREG(rdi, X86ISA::int_reg::Rdi); \
        APPLY_IREG(rsp, X86ISA::int_reg::Rsp); \
        APPLY_IREG(rbp, X86ISA::int_reg::Rbp); \
        APPLY_IREG(r8,  X86ISA::int_reg::R8); \
        APPLY_IREG(r9,  X86ISA::int_reg::R9); \
        APPLY_IREG(r10, X86ISA::int_reg::R10); \
        APPLY_IREG(r11, X86ISA::int_reg::R11); \
        APPLY_IREG(r12, X86ISA::int_reg::R12); \
        APPLY_IREG(r13, X86ISA::int_reg::R13); \
        APPLY_IREG(r14, X86ISA::int_reg::R14); \
        APPLY_IREG(r15, X86ISA::int_reg::R15); \
    } while (0)

void
CPU::syncRegvalToPin(const char *regname, const void *data, size_t size)
{
    // Construct message.
    Message msg;
    msg.type = Message::SetReg;
    std::snprintf(msg.reg.name, sizeof msg.reg.name, "%s", regname);
    assert(size < sizeof msg.reg.data);
    std::memcpy(msg.reg.data, data, size);
    msg.reg.size = size;

    // Send and receive.
    DPRINTF(Pin, "Sending SET_REG for %s\n", regname);
    msg.send(reqFd);
    msg.recv(respFd);
    panic_if(msg.type != Message::Ack, "received response other than ACK (%i): %s!\n", msg.type, msg);    
}

template <typename T>
void
CPU::syncRegvalToPin(const char *regname, T value)
{
    syncRegvalToPin(regname, &value, sizeof value);
}

void
CPU::syncSingleRegToPin(const char *regname, const RegId &reg)
{
    // Read register value.
    std::vector<uint8_t> data(reg.regClass().regBytes());
    tc->getReg(reg, data.data());

    syncRegvalToPin(regname, data.data(), data.size());
}

// TODO: Make into class.
static const std::tuple<const char *, RegIndex, uint8_t, bool> misc_regs[] = {
    {"fs", X86ISA::misc_reg::Fs, 2, false},
    {"gs", X86ISA::misc_reg::Gs, 2, false},
    {"fs_base", X86ISA::misc_reg::FsBase, 8, true},
    {"gs_base", X86ISA::misc_reg::GsBase, 8, true},
    // {"cr4", X86ISA::misc_reg::Cr4, 4, false},
    // {"ftw", X86ISA::misc_reg::Ftw, 2, false}, // NOTE: This is not supported natively by Pin.
    {"fcw", X86ISA::misc_reg::Fcw, 2, false},
    {"fsw", X86ISA::misc_reg::Fsw, 2, false},
    {"ftag", X86ISA::misc_reg::Ftag, 2, false},
};

void
CPU::syncStateToPin(bool full)
{
    // First, copy all GPRs.
    // TODO: Write in standalone function.
#define APPLY_IREG(preg, mreg) syncSingleRegToPin(#preg, mreg)
    FOREACH_IREG();
#undef APPLY_IREG

    // Set instruction pointer.
    syncRegvalToPin("rip", tc->pcState().instAddr());

    // Misc regs.
    for (const auto &[regname, regidx, regsize, always] : misc_regs) {
        if (always || full) {
            const uint64_t regval = tc->readMiscReg(regidx);
            syncRegvalToPin(regname, &regval, regsize);
        }
    }

    // MMX registers.
    if (full) {
#if 0
        for (int i = 0; i < 8; ++i) {
            char name[8];
            sprintf(name, "mm%d", i);
            syncSingleRegToPin(name, X86ISA::float_reg::mmx(i));
        }
#endif
        for (int i = 0; i < 8; ++i) {
            char name[8];
            sprintf(name, "st%d", i);
            const double value64 = bitsToFloat64(tc->getReg(X86ISA::float_reg::fpr(i)));
            uint8_t data80[10];
            X86ISA::storeFloat80(data80, value64);
            syncRegvalToPin(name, data80, sizeof data80);
        }
        for (int i = 0; i < 16; ++i) {
            char name[8];
            sprintf(name, "xmm%d", i);
            union {
                uint64_t words[2];
                uint8_t bytes[16];
            } data;
            data.words[0] = tc->getReg(X86ISA::float_reg::xmmLow(i));
            data.words[1] = tc->getReg(X86ISA::float_reg::xmmHigh(i));
            syncRegvalToPin(name, data.bytes, sizeof data.bytes);
        }
    }
}

void
CPU::syncRegvalFromPin(const char *regname, void *data, size_t size)
{
    // Construct message.
    Message msg;
    msg.type = Message::GetReg;
    std::snprintf(msg.reg.name, sizeof msg.reg.name, "%s", regname);
    msg.reg.size = size;

    // Send and receive.
    DPRINTF(Pin, "Sending GET_REG for %s\n", regname);
    msg.send(reqFd);
    msg.recv(respFd);
    panic_if(msg.type != Message::SetReg, "received response other than SET_REG (%i): %s\n", msg.type, msg);

    // Set register.
    panic_if(msg.reg.size != size, "Got bad register size\n");
    panic_if(std::strncmp(msg.reg.name, regname, sizeof msg.reg.name) != 0, "Got bad register name\n");
    std::memcpy(data, msg.reg.data, size);
}

template <typename T>
T
CPU::syncRegvalFromPin(const char *name)
{
    T value;
    syncRegvalFromPin(name, &value, sizeof value);
    return value;
}

void
CPU::syncRegFromPin(const char *regname, const RegId &reg)
{
    std::vector<uint8_t> buf(reg.regClass().regBytes());
    syncRegvalFromPin(regname, buf.data(), buf.size());

    if (buf.size() == 8)
        DPRINTF(Pin, "GET_REG: %s %x\n", regname, * (const uint64_t *) buf.data());
    
    tc->setReg(reg, buf.data());
}

void
CPU::syncStateFromPin(bool full)
{
    // First, copy all GPRs.
#define APPLY_IREG(preg, mreg) syncRegFromPin(#preg, mreg)
    FOREACH_IREG();
#undef APPLY_REG

    // Get instruction pointer.
    tc->pcState(syncRegvalFromPin<Addr>("rip"));

    // Misc registers.
    for (const auto &[regname, regidx, regsize, always] : misc_regs) {
        if (full || always) {
            assert(regsize <= 8);
            uint64_t regval;
            syncRegvalFromPin(regname, &regval, regsize);
            tc->setMiscRegNoEffect(regidx, regval);
        }
    }

    // FP registers.
    if (full) {
#if 0
        for (int i = 0; i < 8; ++i) {
            char name[8];
            sprintf(name, "mm%d", i);
            syncRegFromPin(name, X86ISA::float_reg::mmx(i));
        }
#endif
        for (int i = 0; i < 8; ++i) {
            char name[8];
            sprintf(name, "st%d", i);
            uint8_t data80[10];
            syncRegvalFromPin(name, data80, sizeof data80);
            const double value64 = X86ISA::loadFloat80(data80);
            tc->setReg(X86ISA::float_reg::fpr(i), floatToBits64(value64));
        }
        for (int i = 0; i < 16; ++i) {
            char name[8];
            sprintf(name, "xmm%d", i);
            union {
                uint64_t words[2];
                uint8_t bytes[16];
            } data;
            syncRegvalFromPin(name, data.bytes, sizeof data.bytes);
            tc->setReg(X86ISA::float_reg::xmmLow(i), data.words[0]);
            tc->setReg(X86ISA::float_reg::xmmHigh(i), data.words[1]);
        }
    }
}

void
CPU::pinRun()
{
    syncStateToPin(false);

    // Tell it to run.
    Message msg;
    msg.type = Message::Run;
    msg.send(reqFd);
    msg.recv(respFd);
    if (ctrInsts) {
        assert(*ctrInsts <= msg.inst_count);
        ctrInsts = (uint64_t) msg.inst_count;
    }
        
    switch (msg.type) {
      case Message::PageFault:
        handlePageFault(msg.faultaddr);
        break;

      case Message::Syscall:
        handleSyscall();
        break;

      case Message::Cpuid:
        handleCPUID();
        break;

      case Message::Ack:
        break;
        
      default:
        panic("unhandled run response type (%d)\n", msg.type);
    }
}

void
CPU::handlePageFault(Addr vaddr)
{
    syncStateFromPin(false);
  
    DPRINTF(Pin, "vaddr=%x\n", vaddr);
    assert(vaddr);
    vaddr &= ~ (Addr) 0xfff;
    const auto ptr = tc->getMMUPtr()->translateFunctional(vaddr, 0x1000, tc, BaseMMU::Read, 0);
    assert(ptr);
    bool handled = false;
    for (const TranslationGen::Range &range : *ptr) {
        DPRINTF(Pin, "Handling page fault: vaddr=%x paddr=%x size=%i fault=%s\n", range.vaddr, range.paddr, range.size, range.fault);
        assert(range.size == 0x1000);
	if (range.fault != NoFault) {
            panic("Page fault: vaddr=%x fault=%s\n", range.vaddr, range.fault->name());
	}

        Message msg;
        msg.type = Message::Map;
        msg.map.vaddr = range.vaddr;
        msg.map.paddr = range.paddr;
        msg.send(reqFd);
        msg.recv(respFd);
        panic_if(msg.type != Message::Ack, "unexpected response\n");

        handled = true;
    }

    panic_if(!handled, "didn't handle page fault\n");
}

Tick
CPU::doMMIOAccess(Addr paddr, void *data, int size, bool write)
{
    // TODO: Remove this entirely.
    fatal("delete this bloody function\n");
    
    // NOTE: Might need to stutterPC like in KVM:
    // pc.as<X86ISA::PCState>().setNPC(pc.instAddr()); 
    syncStateFromPin(false);

    RequestPtr mmio_req = std::make_shared<Request>(
        paddr, size, Request::UNCACHEABLE, dataRequestorId());

    mmio_req->setContext(tc->contextId());

    // Skip finalization of MMIO physical address.

    const MemCmd cmd(write ? MemCmd::WriteReq : MemCmd::ReadReq);
    PacketPtr pkt = new Packet(mmio_req, cmd);
    pkt->dataStatic(data);

    warn_if(!mmio_req->isLocalAccess(), "MMIO request is not local access. I have no clue what this means.\n");

    const Cycles ipr_delay = mmio_req->localAccessor(tc, pkt);
    // threadContextDirty = true;
    delete pkt;
    return clockPeriod() * ipr_delay;
}

void
CPU::handleSyscall()
{
    syncStateFromPin(false);

    tc->getSystemPtr()->workload->syscall(tc);

    // FIXME: Need to cleanly exit. 
}

void
CPU::handleCPUID()
{
    syncStateFromPin(false);

    // Get function (EAX).
    const uint32_t func = tc->getReg(X86ISA::int_reg::Rax);

    // Get index (ECX).
    const uint32_t index = tc->getReg(X86ISA::int_reg::Rcx);

    DPRINTF(Pin, "CPUID: EAX=0x%x ECX=0x%x\n", func, index);
    
    // Do CPUID.
    X86ISA::ISA *isa = dynamic_cast<X86ISA::ISA *>(tc->getIsaPtr());
    X86ISA::CpuidResult result;
    isa->cpuid->doCpuid(tc, func, index, result);

    // Set RAX, RBX, RCX, RDX.
    tc->setReg(X86ISA::int_reg::Rax, result.rax);
    tc->setReg(X86ISA::int_reg::Rbx, result.rbx);
    tc->setReg(X86ISA::int_reg::Rdx, result.rdx);
    tc->setReg(X86ISA::int_reg::Rcx, result.rcx);
}

}
}
