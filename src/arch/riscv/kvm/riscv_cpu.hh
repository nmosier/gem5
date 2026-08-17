/*
 * Copyright (c) 2026 The Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __ARCH_RISCV_KVM_RISCV_CPU_HH__
#define __ARCH_RISCV_KVM_RISCV_CPU_HH__

#include <vector>

/* Before regs/misc.hh: that header uses RiscvISA::RV32/RV64, which are
 * declared in pcstate.hh, and does not include it itself. */
#include "arch/riscv/pcstate.hh"
#include "arch/riscv/regs/misc.hh"
#include "cpu/kvm/base.hh"
#include "params/RiscvKvmCPU.hh"

namespace gem5
{

/**
 * RISC-V-specific KVM CPU.
 *
 * RISC-V's KVM interface is almost entirely KVM_GET_ONE_REG and
 * KVM_SET_ONE_REG: there is no equivalent of x86's KVM_GET_REGS or Arm's
 * register file structures, so synchronising a context is a matter of walking
 * the maps below, one register at a time in each direction.
 */
class RiscvKvmCPU : public BaseKvmCPU
{
  public:
    RiscvKvmCPU(const RiscvKvmCPUParams &params);
    virtual ~RiscvKvmCPU() = default;

    Tick kvmRun(Tick ticks) override;
    void dump() const override;
    void updateKvmState() override;
    void updateThreadContext() override;

    /**
     * KVM has already advanced the PC past the instruction that exited, so
     * there is no next PC to hand to gem5.  Point it back at the current one,
     * which is what anything asking will find least surprising.
     */
    void
    stutterPC(PCStateBase &pc) const override
    {
        pc.as<RiscvISA::PCState>().npc(pc.instAddr());
    }

  protected:
    /** A supervisor CSR, and the gem5 register holding the same thing. */
    struct CSRInfo
    {
        CSRInfo(uint64_t kvm, RiscvISA::MiscRegIndex idx, const char *name)
            : kvm(kvm), idx(idx), name(name)
        {}

        uint64_t kvm;
        RiscvISA::MiscRegIndex idx;
        const char *name;
    };

    static const std::vector<RiscvKvmCPU::CSRInfo> csrMap;
};

} // namespace gem5

#endif // __ARCH_RISCV_KVM_RISCV_CPU_HH__
