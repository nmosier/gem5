# Copyright (c) 2026 The Regents of the University of California
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met: redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer;
# redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution;
# neither the name of the copyright holders nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Boot Ubuntu on one ARM KVM core.

This is arm-ubuntu-run-with-kvm.py reduced to the smallest thing that still
exercises the KVM path: a single core that stays KVM for the whole run, with
no switch to a timing model.  It is the ARM counterpart of
x86-ubuntu-run-with-kvm-no-perf.py, and it is meant for bringing the KVM
backend up rather than for taking measurements.

ArmBoard notices that the processor has KVM cores and configures the platform
accordingly -- in particular it sets `simulate_gic`, so gem5 models the
interrupt controller itself and interrupts reach the CPU over its IRQ line
rather than through an in-kernel VGIC.

Usage:
  QVM_PATH=<qemu> QVM_BUILD=<qemu>/build-arm QVM_ISA=arm64 \
      scons build/ARM/gem5.opt
  ./build/ARM/gem5.opt \
      configs/example/gem5_library/arm-ubuntu-run-with-kvm-1core.py
"""

from m5.objects import (
    ArmDefaultRelease,
    VExpress_GEM5_V1,
)

from gem5.components.boards.arm_board import ArmBoard
from gem5.components.cachehierarchies.classic.private_l1_private_l2_cache_hierarchy import (
    PrivateL1PrivateL2CacheHierarchy,
)
from gem5.components.memory import DualChannelDDR4_2400
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_processor import SimpleProcessor
from gem5.isas import ISA
from gem5.resources.resource import obtain_resource
from gem5.simulate.simulator import Simulator

cache_hierarchy = PrivateL1PrivateL2CacheHierarchy(
    l1d_size="16KiB", l1i_size="16KiB", l2_size="256KiB"
)

memory = DualChannelDDR4_2400(size="2GiB")

processor = SimpleProcessor(cpu_type=CPUTypes.KVM, isa=ISA.ARM, num_cores=1)

# for_kvm() adds the extensions the KVM path needs to the release.
release = ArmDefaultRelease.for_kvm()

# ARM KVM only works with VExpress_GEM5_V1 on the ArmBoard at the moment.
platform = VExpress_GEM5_V1()

board = ArmBoard(
    clk_freq="3GHz",
    processor=processor,
    memory=memory,
    cache_hierarchy=cache_hierarchy,
    release=release,
    platform=platform,
)

board.set_workload(
    obtain_resource("arm-ubuntu-24.04-boot-with-systemd", resource_version="3.0.0")
)

simulator = Simulator(board=board)
simulator.run()

print(
    "Exiting @ tick "
    f"{simulator.get_current_tick()} because "
    f"{simulator.get_last_exit_event_cause()}"
)
