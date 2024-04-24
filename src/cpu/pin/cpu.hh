#pragma once

#include <memory>

#include "cpu/base.hh"

namespace gem5
{

// Forward declarations.
class SimpleThread;
class BasePinCPUParams;
class System;

namespace pin
{

class CPU final : public BaseCPU
{
  public:
    CPU(const BasePinCPUParams &params);

    void init() override;
    void startup() override;
    void activateContext(ThreadID tid = 0) override;

    class PinRequestPort final : public RequestPort
    {
      public:
        PinRequestPort(const std::string &name, CPU *cpu)
            : RequestPort(name), cpu(cpu)
        {
        }

      private:
        CPU *cpu;

        bool recvTimingResp(PacketPtr pkt) override;
        void recvReqRetry() override;
    };

    Port &getDataPort() override;
    Port &getInstPort() override;
    void wakeup(ThreadID tid) override;
    Counter totalInsts() const override;
    Counter totalOps() const override;

    void tick();

    enum Status
    {
        Idle,
        Running,
    };

  private:
    std::unique_ptr<SimpleThread> thread;
    ThreadContext *tc;
    EventFunctionWrapper tickEvent;
    Status _status;
    PinRequestPort dataPort;
    PinRequestPort instPort;
    pid_t pinPid;
    int pinFd;
    System *system;

    static const char *getPinRoot();
    static const char *getPinTool();
    static std::string getPinExe();
    static const char *getFifoPath();
    static std::string getDummyProg();

    void pinRun();


};

}
}
