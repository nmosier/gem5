#include "cpu/pin/cpu.hh"

#include <cstdlib>
#include <fcntl.h>
#include <sys/wait.h>

#include "cpu/simple_thread.hh"
#include "params/BasePinCPU.hh"
#include "cpu/pin/message.hh"
#include "debug/Pin.hh"
#include "sim/system.hh"

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
CPU::getFifoPath()
{
    const char *fifo_path = std::getenv("PIN_FIFO");
    fatal_if(fifo_path == nullptr, "environment variable PIN_FIFO not set!");
    return fifo_path;
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

    const std::string fifo_path = getFifoPath();
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
            "--", dummy_prog.c_str(), // TODO: Replace with real program.
	    fifo_path.c_str(), shm_path.c_str(),
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
    pinFd = open(fifo_path.c_str(), O_RDWR);
    fatal_if(pinFd < 0, "open failed: %s: %s", fifo_path.c_str(), std::strerror(errno));

    // Send initial ACK.
    Message msg;
    msg.type = Message::Ack;
    DPRINTF(Pin, "Sending initial ACK\n");
    msg.send(pinFd);
    DPRINTF(Pin, "Receiving initial ACK\n");
    msg.recv(pinFd);
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

void
CPU::pinRun()
{
    fatal("unimplemented: pinRun");
}

}
}
