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
Instrument a KVM-simulated guest with a QEMU TCG plugin.

A KVM CPU normally runs the guest on the host's own hardware, where there is
nothing to instrument.  On QVM the guest is translated, so QEMU's plugins can
watch it -- and gem5 can ask for one through KvmVM.loadPlugin(), the same way
it asks for anything else about the machine.

This runs a workload under X86KvmCPU with contrib/plugins/bbv.c attached, which
records a basic block vector: how often each block executed, in intervals.

Usage:
  QVM_PATH=<qemu> scons build/X86/gem5.opt
  ./build/X86/gem5.opt configs/example/qvm-plugin-bbv.py \
      --plugin <qemu>/build/contrib/plugins/libbbv.so
"""

import argparse
import os

from gem5.components.boards.simple_board import SimpleBoard
from gem5.components.cachehierarchies.classic.no_cache import NoCache
from gem5.components.memory import SingleChannelDDR3_1600
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_processor import SimpleProcessor
from gem5.isas import ISA
from gem5.resources.resource import BinaryResource
from gem5.simulate.simulator import Simulator

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--plugin",
    required=True,
    help="path to the TCG plugin shared object, e.g. libbbv.so",
)
parser.add_argument(
    "--plugin-args",
    default="outfile=m5out/bbv,interval=1000",
    help="plugin arguments, in QEMU's name=value,name=value form",
)
parser.add_argument(
    "--binary",
    default="tests/test-progs/hello/bin/x86/linux/hello",
    help="workload to run",
)
args = parser.parse_args()

processor = SimpleProcessor(cpu_type=CPUTypes.KVM, isa=ISA.X86, num_cores=1)

board = SimpleBoard(
    clk_freq="3GHz",
    processor=processor,
    memory=SingleChannelDDR3_1600(size="512MiB"),
    cache_hierarchy=NoCache(),
)
board.set_se_binary_workload(BinaryResource(os.path.abspath(args.binary)))

simulator = Simulator(board=board, full_system=False)

# The VM has to exist before it can be asked for anything, and it is created
# when the simulation is instantiated -- so instantiate first, then load, then
# run.  QVM accepts a plugin at either point; one loaded now discards any code
# translated during setup so that it is instrumented on its next execution.
simulator._instantiate()

print(f"Loading TCG plugin {args.plugin} ({args.plugin_args})")
processor.kvm_vm.loadPlugin(args.plugin, args.plugin_args)

simulator.run()

print(
    "Exiting @ tick "
    f"{simulator.get_current_tick()} because "
    f"{simulator.get_last_exit_event_cause()}"
)
