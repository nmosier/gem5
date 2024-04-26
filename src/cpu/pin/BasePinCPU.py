from m5.defines import buildEnv
from m5.objects.BaseCPU import BaseCPU
from m5.params import *

class BasePinCPU(BaseCPU):
    type = "BasePinCPU"
    cxx_header = "cpu/pin/cpu.hh"
    cxx_class = "gem5::pin::CPU"

    @classmethod
    def memory_mode(cls):
        return "atomic"

    @classmethod
    def support_take_over(cls):
        return False

    countInsts = Param.Bool(True, "Enable instruction counting (moderate performance penalty)")
    traceInsts = Param.Bool(False, "Enable instruction tracing (huge performance penalty)")
