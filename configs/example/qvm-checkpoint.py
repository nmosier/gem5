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
Fast-forward on QVM to an exact instruction count, checkpoint, and resume
somewhere else.

This is the workflow a KVM CPU exists for -- run the uninteresting part of a
workload quickly, then study a slice of it in detail -- and it needs three
things from the emulator underneath: an exact instruction count, a stop on an
exact instruction boundary, and a vCPU that can be brought to a halt with
nothing left half-delivered.

  --mode take     run to --insts instructions on QVM and checkpoint there
  --mode resume   restore that checkpoint on --cpu and run --resume-insts more

Usage:
  ./build/X86/gem5.opt configs/example/qvm-checkpoint.py --mode take
  ./build/X86/gem5.opt configs/example/qvm-checkpoint.py --mode resume \
      --cpu timing --resume-insts 50000
"""

import argparse
import os
from pathlib import Path

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
    "--mode", choices=["take", "resume", "multi"], required=True
)
parser.add_argument(
    "--insts",
    type=int,
    default=1_000_000,
    help="instruction count to stop and checkpoint at",
)
parser.add_argument(
    "--resume-insts",
    type=int,
    default=50_000,
    help="instructions to simulate after restoring",
)
parser.add_argument(
    "--cpu",
    choices=["kvm", "timing", "atomic"],
    default="timing",
    help="CPU to restore onto",
)
parser.add_argument("--ckpt", default="m5out-ckpt/cpt", help="checkpoint dir")
parser.add_argument(
    "--stops",
    type=int,
    default=3,
    help="multi mode: how many breakpoints, spaced --insts apart",
)
parser.add_argument(
    "--binary",
    default="tests/test-progs/hello/bin/x86/linux/hello",
    help="workload to run",
)
args = parser.parse_args()

CPU_TYPES = {
    "kvm": CPUTypes.KVM,
    "timing": CPUTypes.TIMING,
    "atomic": CPUTypes.ATOMIC,
}

# Taking the checkpoint is the part that has to be fast, so that is the part
# that runs on QVM.  Restoring deliberately does not: the point is to arrive
# somewhere interesting and then switch to a model that can tell you something.
cpu_type = CPUTypes.KVM if args.mode != "resume" else CPU_TYPES[args.cpu]

processor = SimpleProcessor(cpu_type=cpu_type, isa=ISA.X86, num_cores=1)

board = SimpleBoard(
    clk_freq="3GHz",
    processor=processor,
    memory=SingleChannelDDR3_1600(size="512MiB"),
    cache_hierarchy=NoCache(),
)
ckpt = Path(args.ckpt)

# Restoring is a property of the workload, not of the Simulator: the board
# needs to know at build time that its memory and thread state come from disk.
board.set_se_binary_workload(
    BinaryResource(os.path.abspath(args.binary)),
    checkpoint=ckpt if args.mode == "resume" else None,
)

if args.mode == "multi":
    # What a SimPoint run does: stop at each chosen instruction count in one
    # pass, checkpointing as it goes.  Each stop has to land exactly, or the
    # sample starts somewhere other than the interval that was selected.
    simulator = Simulator(board=board, full_system=False)

    for i in range(1, args.stops + 1):
        target = args.insts * i
        # schedule_max_insts() is relative to where the CPU already is:
        # BaseCPU::scheduleInstStop() schedules at getCurrentInstCount() +
        # insts.  So each stop asks for the same delta, not the running total.
        simulator.schedule_max_insts(args.insts)
        simulator.run()

        got = simulator.get_instruction_count()
        print(
            f"[multi] stop {i}: asked {target}, got {got}, "
            f"{'exact' if got == target else 'OFF BY ' + str(got - target)}"
        )

        out = Path(f"{args.ckpt}-{i}")
        out.mkdir(parents=True, exist_ok=True)
        simulator.save_checkpoint(out)
elif args.mode == "take":
    simulator = Simulator(board=board, full_system=False)
    simulator.schedule_max_insts(args.insts)
    simulator.run()

    executed = simulator.get_instruction_count()
    print(f"\n[take] stopped after {executed} instructions")
    print(f"[take] exit cause: {simulator.get_last_exit_event_cause()}")

    ckpt.mkdir(parents=True, exist_ok=True)
    simulator.save_checkpoint(ckpt)
    print(f"[take] checkpoint written to {ckpt}")
else:
    simulator = Simulator(board=board, full_system=False)
    simulator.schedule_max_insts(args.resume_insts)
    simulator.run()

    print(f"\n[resume] restored onto {cpu_type}")
    print(
        f"[resume] simulated {simulator.get_instruction_count()} "
        "instructions after the checkpoint"
    )
    print(f"[resume] exit cause: {simulator.get_last_exit_event_cause()}")
    print(f"[resume] tick {simulator.get_current_tick()}")
