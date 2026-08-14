/*
 * The out-of-line part of the perf_event stand-ins in perfevent.hh, for hosts
 * that have no perf_event to build against.
 */

#include "base/logging.hh"
#include "config/use_perf_event.hh"
#include "cpu/kvm/perfevent.hh"

#if !USE_PERF_EVENT

namespace gem5
{

void
PerfKvmCounter::unsupported()
{
    panic("KVM: this host has no perf_event, so the guest's cycles and "
          "instructions cannot be counted. Set BaseKvmCPU.usePerf=False.");
}

} // namespace gem5

#endif // !USE_PERF_EVENT
