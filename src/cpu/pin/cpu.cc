#include "cpu/pin/cpu.hh"

#include <cstdlib>
#include <fcntl.h>
#include <sys/wait.h>

#include "cpu/simple_thread.hh"
#include "params/BasePinCPU.hh"
#include "cpu/pin/message.hh"
#include "debug/Pin.hh"
#include "sim/system.hh"
#include "arch/x86/regs/int.hh"

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
      system(params.system)
{
    thread = std::make_unique<SimpleThread>(
        this, /*thread_num*/0, params.system,
        params.workload[0], params.mmu,
        params.isa[0], params.decoder[0]);
    thread->setStatus(ThreadContext::Halted);
    tc = thread->getTC();
    threadContexts.push_back(tc);
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
    fatal("Unsupported: %s", __func__);
}

Counter
CPU::totalOps() const
{
    fatal("Unsupported: %s", __func__);
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

    const std::string req_path = getRequestPath();
    const std::string resp_path = getResponsePath();
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
        // This is the Pin subprocess. Execute pin.
        std::vector<const char *> args = {
            pin_exe.c_str(),
	    // "-pin_memory_range", "0x8000000000:0x9000000000",
            "-t", pin_tool.c_str(),
	    "-log", "pin.log",
	    "-req_path", req_path.c_str(),
            "-resp_path", resp_path.c_str(),
	    "-mem_path", shm_path.c_str(),
            "--", dummy_prog.c_str(), // TODO: Replace with real program.
            nullptr,
        };
        char **argv = const_cast<char **>(args.data());

	std::stringstream cmd_ss;
	for (const char *arg : args)
	  cmd_ss << arg << " ";
	DPRINTF(Pin, "%s\n", cmd_ss.str());

        execvp(argv[0], argv);
        fatal("execvp failed: %s", std::strerror(errno));
    }

    // Open fifo.
    reqFd = open(req_path.c_str(), O_WRONLY);
    fatal_if(reqFd < 0, "open failed: %s: %s", req_path, std::strerror(errno));
    respFd = open(resp_path.c_str(), O_RDONLY);
    fatal_if(respFd < 0, "open failed: %s: %s", resp_path, std::strerror(errno));

    // Send initial ACK.
    Message msg;
    msg.type = Message::Ack;
    DPRINTF(Pin, "Sending initial ACK\n");
    msg.send(reqFd);
    DPRINTF(Pin, "Receiving initial ACK\n");
    msg.recv(respFd);
    panic_if(msg.type != Message::Ack, "Received message other than ACK at pintool startup!\n");
    DPRINTF(Pin, "received ACK from pintool\n");

    // Copy over memory state.
    // tc->getMMUPtr()

    warn("Pin::CPU::startup not complete\n");
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

    warn("TODO: sync gem5->Pin state here\n");

    pinRun(); // TODO: Will need to communicate how many ticks required.

    ++delay; // FIXME

    if (_status != Idle) {
        schedule(tickEvent, clockEdge(ticksToCycles(delay)));
    }
}

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
CPU::syncRegvalToPin(const char *regname, void *data, size_t size)
{
    // Construct message.
    Message msg;
    msg.type = Message::SetReg;
    std::strncpy(msg.reg.name, regname, sizeof msg.reg.name);
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

void
CPU::syncStateToPin()
{
    // First, copy all GPRs.
    // TODO: Write in standalone function.
#define APPLY_IREG(preg, mreg) syncSingleRegToPin(#preg, mreg)
    FOREACH_IREG();
#undef APPLY_IREG

    // Set instruction pointer.
    syncRegvalToPin("rip", tc->pcState().instAddr());
}

void
CPU::pinRun()
{
    syncStateToPin();

    // Tell it to run.
    Message msg;
    msg.type = Message::Run;
    msg.send(reqFd);
    msg.recv(respFd);
    switch (msg.type) {
      default:
        panic("unhandled run response type (%d)\n", msg.type);
    }    
    fatal("unimplemented: pinRun");
}

}
}
