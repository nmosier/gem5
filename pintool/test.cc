#include "pin.H"

#include <iostream>

static bool InterceptSEGV(THREADID tid, int32_t sig, CONTEXT *ctx, bool has_handler, const EXCEPTION_INFO *info, void *) {
  std::cerr << "Caught SEGV: " << info->ToString() << "\n";
  return true;
}

int main(int argc, char *argv[]) {
  if (PIN_Init(argc, argv)) {
    std::cerr << KNOB_BASE::StringKnobSummary() << "\n";
    return 1;
  }

  PIN_InterceptSignal(SIGSEGV, InterceptSEGV, nullptr);

  PIN_StartProgram();
}
