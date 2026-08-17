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

#include "arch/riscv/kvm/riscv_cpu.hh"

#include <cstddef>

#include "arch/riscv/interrupts.hh"
#include "arch/riscv/pcstate.hh"
#include "arch/riscv/regs/int.hh"
#include "cpu/kvm/api.hh"
#include "debug/Kvm.hh"
#include "debug/KvmContext.hh"
#include "debug/KvmInt.hh"

/*
 * struct user_regs_struct is { pc, x1 ... x31 }, so a core register index is
 * zero for the PC or the number of the general register it names, and the
 * privilege mode follows the array.
 */
#define CORE_REG(idx) \
    (KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CORE | (idx))

#define CORE_REG_PC   CORE_REG(0)
#define CORE_REG_MODE \
    CORE_REG(offsetof(struct kvm_riscv_core, mode) / sizeof(unsigned long))

/* The guest's timebase, which the DTB also advertises to it. */
#define RISCV_TIMEBASE_HZ 1000000ULL

#define TIMER_REG(field)                                                    \
    (KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_TIMER |               \
     (offsetof(struct kvm_riscv_timer, field) / sizeof(__u64)))

#define CSR_REG(field)                                                      \
    (KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CSR |                 \
     KVM_REG_RISCV_CSR_GENERAL |                                            \
     (offsetof(struct kvm_riscv_csr, field) / sizeof(unsigned long)))

namespace gem5
{

/*
 * The supervisor state a guest carries between runs.  gem5 names most of
 * these by the CSR they are, but its sstatus and sip are MISCREG_STATUS and
 * MISCREG_IP -- one register per privilege view rather than one per name.
 */
const std::vector<RiscvKvmCPU::CSRInfo> RiscvKvmCPU::csrMap = {
    CSRInfo(CSR_REG(sstatus),  RiscvISA::MISCREG_STATUS,   "sstatus"),
    CSRInfo(CSR_REG(sie),      RiscvISA::MISCREG_IE,       "sie"),
    CSRInfo(CSR_REG(stvec),    RiscvISA::MISCREG_STVEC,    "stvec"),
    CSRInfo(CSR_REG(sscratch), RiscvISA::MISCREG_SSCRATCH, "sscratch"),
    CSRInfo(CSR_REG(sepc),     RiscvISA::MISCREG_SEPC,     "sepc"),
    CSRInfo(CSR_REG(scause),   RiscvISA::MISCREG_SCAUSE,   "scause"),
    CSRInfo(CSR_REG(stval),    RiscvISA::MISCREG_STVAL,    "stval"),
    CSRInfo(CSR_REG(sip),      RiscvISA::MISCREG_IP,       "sip"),
    CSRInfo(CSR_REG(satp),     RiscvISA::MISCREG_SATP,     "satp"),
};

RiscvKvmCPU::RiscvKvmCPU(const RiscvKvmCPUParams &params)
    : BaseKvmCPU(params)
{
}

Tick
RiscvKvmCPU::kvmRun(Tick ticks)
{
    auto *ic = dynamic_cast<RiscvISA::Interrupts *>(interrupts[0]);

    /*
     * gem5's devices post interrupts into its own controller whenever they
     * like, including while the guest is running.  RISC-V has no
     * KVM_INTERRUPT to hand one over with: an interrupt is delivered by
     * writing the pending register, so that is what happens here, on the way
     * in.  Reading it back out of the controller rather than from the cached
     * context is deliberate -- the controller is what the device just posted
     * to.
     */
    if (ic) {
        /*
         * The interrupt-pending bits have two owners.  The hardware lines --
         * external, machine timer, machine software -- belong to this side:
         * the PLIC and CLINT are gem5 devices, and level-sensitive lines have
         * to be withdrawn as well as raised, or a guest whose line never
         * drops claims from a controller with nothing to give, for ever.  The
         * supervisor timer and software bits belong to the guest: its own
         * machine-mode firmware raises STIP for the kernel, and pushing our
         * stale copy over it would erase an interrupt between firmware
         * raising it and the kernel taking it.
         */
        constexpr uint64_t hw_lines(
            (1 << 11) | (1 << 7) | (1 << 3) | (1 << 9));

        const uint64_t cur(getOneRegU64(CSR_REG(sip)));
        const uint64_t ip(tc->readMiscReg(RiscvISA::MISCREG_IP));
        const uint64_t next((cur & ~hw_lines) | (ip & hw_lines));

        if (next != cur) {
            DPRINTF(KvmInt, "Interrupt lines: sip 0x%x -> 0x%x\n", cur, next);
            setOneReg(CSR_REG(sip), next);
        }
    }

    /*
     * Hand the guest our clock.  It reads the time, adds an interval and asks
     * the timer for an interrupt then -- and the device deciding when "then"
     * has arrived is on this side, running on simulated time.  If the guest
     * were reading some other clock it would be arming deadlines against a
     * time that never comes.
     */
    setOneReg(TIMER_REG(time),
              curTick() / (sim_clock::as_int::s / RISCV_TIMEBASE_HZ));

    return BaseKvmCPU::kvmRun(ticks);
}

void
RiscvKvmCPU::dump() const
{
    inform("PC: 0x%x\n", getOneRegU64(CORE_REG_PC));
    for (int i = 1; i < RiscvISA::int_reg::NumArchRegs; ++i) {
        inform("  x%i: 0x%x\n", i, getOneRegU64(CORE_REG(i)));
    }
    for (const auto &csr : csrMap) {
        inform("  %s: 0x%x\n", csr.name, getOneRegU64(csr.kvm));
    }
}

void
RiscvKvmCPU::updateKvmState()
{
    DPRINTF(KvmContext, "Updating KVM state...\n");

    setOneReg(CORE_REG_PC, tc->pcState().instAddr());

    /*
     * x0 is hardwired to zero and is not part of the register file KVM
     * exchanges, so the loop starts at one.
     */
    for (int i = 1; i < RiscvISA::int_reg::NumArchRegs; ++i) {
        setOneReg(CORE_REG(i), tc->getReg(RiscvISA::intRegClass[i]));
    }

    setOneReg(CORE_REG_MODE, tc->readMiscReg(RiscvISA::MISCREG_PRV));

    for (const auto &csr : csrMap) {
        DPRINTF(KvmContext, "  %s := 0x%x\n", csr.name,
                tc->readMiscReg(csr.idx));
        setOneReg(csr.kvm, tc->readMiscReg(csr.idx));
    }
}

void
RiscvKvmCPU::updateThreadContext()
{
    DPRINTF(KvmContext, "Updating gem5 state...\n");

    for (int i = 1; i < RiscvISA::int_reg::NumArchRegs; ++i) {
        tc->setReg(RiscvISA::intRegClass[i], getOneRegU64(CORE_REG(i)));
    }

    tc->setMiscRegNoEffect(RiscvISA::MISCREG_PRV,
                           getOneRegU64(CORE_REG_MODE));

    for (const auto &csr : csrMap) {
        const uint64_t value(getOneRegU64(csr.kvm));
        DPRINTF(KvmContext, "  %s := 0x%x\n", csr.name, value);

        /*
         * sip and sie are not stored registers on this side either: reading
         * or writing them goes through the interrupt controller, which is
         * where gem5 keeps what is pending and what is enabled.  Writing them
         * without effect would drop the guest's acknowledgement of an
         * interrupt on the floor, and gem5 would post it again for ever.
         */
        if (csr.idx == RiscvISA::MISCREG_IP) {
            /*
             * Write back only the bits the guest owns.  The hardware lines
             * are gem5's -- the PLIC and CLINT raise and lower them -- and
             * copying the guest's view of them back into the interrupt
             * controller would turn a line the device released into one that
             * never drops: the next entry reads the copy, sees nothing to
             * withdraw, and the guest is interrupted by its own echo.
             */
            constexpr uint64_t guest_bits((1 << 5) | (1 << 1));
            const uint64_t cur(tc->readMiscReg(RiscvISA::MISCREG_IP));

            tc->setMiscReg(csr.idx,
                           (cur & ~guest_bits) | (value & guest_bits));
        } else if (csr.idx == RiscvISA::MISCREG_IE) {
            tc->setMiscReg(csr.idx, value);
        } else {
            tc->setMiscRegNoEffect(csr.idx, value);
        }
    }

    /*
     * Last, because setting the CSRs above can change how the PC is
     * interpreted -- the privilege mode selects the translation regime.
     */
    RiscvISA::PCState pc = tc->pcState().as<RiscvISA::PCState>();
    pc.set(getOneRegU64(CORE_REG_PC));
    tc->pcState(pc);
}

} // namespace gem5
