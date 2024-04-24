#include "cpu/pin/cpu.hh"

#include <cstdlib>

#include "cpu/simple_thread.hh"
#include "params/BasePinCPU.hh"
#include "cpu/pin/message.hh"

namespace gem5
{

namespace pin
{

CPU::CPU(const BasePinCPUParams &params)
    : BaseCPU(params),
      tickEvent([this] { tick(); }, "BasePinCPU tick", false, Event::CPU_Tick_Pri),
      _status(Idle),
      dataPort(name() + ".dcache_port", this),
      instPort(name() + ".icache_port", this)
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
    return std::string(getPinRoot()) + "/dummy";
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

    pinPid = fork();
    if (pinPid < 0) {
        fatal("fork: %s", std::strerror(errno));
    } else if (pinPid == 0) {
        // This is the Pin subprocess. Execute pin.
        std::vector<const char *> args = {
            pin_exe.c_str(),
            "-t", pin_tool.c_str(),
            "-fifo", fifo_path.c_str(),
	    "-log", "pin.log",
            "--",
            dummy_prog.c_str(), // TODO: Replace with real program.
        };
        char **argv = const_cast<char **>(args.data());
        execvp(argv[0], argv);
        fatal("execvp failed: %s", std::strerror(errno));
    }
    
    // Open fifo.
    pinFd = open(fifo_path.c_str(), O_RDWR);
    fatal_if(pinFd < 0, "open failed: %s: %s", fifo_path.c_str(), std::strerror(errno));

    // Read initial ACK.
    Message msg;
    msg.recv(pinFd);
    std::cerr << "pincpu: got message\n";
    assert(msg.type == Message::Ack);
    exit(1);
    
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
