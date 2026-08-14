#pragma once

#include <cstddef>

#include "config/use_qvm.hh"

/*
 * The KVM ABI: request numbers, structures and exit reasons.
 *
 * This is the only place gem5 pulls them in.  On a Linux host they are the
 * kernel's own UAPI headers; when building against QVM they are the copy it
 * ships, which is what lets the rest of the KVM CPU code compile unchanged on
 * a host that has no /dev/kvm -- or whose /dev/kvm speaks a different ISA.
 * Either way the definitions are identical, because QVM implements this ABI
 * rather than one of its own.
 */
#include <linux/kvm.h>

/*
 * Which ISA's KVM ABI the headers above describe.
 *
 * This is not the same question as what the host CPU is, which is what the
 * code here used to ask.  The host kernel's KVM only ever speaks its own ISA,
 * so the two coincided; QVM does not, and always presents an x86 guest.  On an
 * aarch64 host running QVM, then, these headers describe x86, and the ARM-only
 * requests -- along with the structures they take -- are simply not there.
 */
#if USE_QVM
#define KVM_ABI_IS_X86 1
#define KVM_ABI_IS_ARM 0
#elif defined(__aarch64__) || defined(__arm__)
#define KVM_ABI_IS_X86 0
#define KVM_ABI_IS_ARM 1
#elif defined(__i386__) || defined(__x86_64__)
#define KVM_ABI_IS_X86 1
#define KVM_ABI_IS_ARM 0
#else
#define KVM_ABI_IS_X86 0
#define KVM_ABI_IS_ARM 0
#endif

namespace gem5
{

/**
 * The calls gem5 makes against a KVM descriptor.
 *
 * There are two implementations: the host kernel's, in api_kvm.cc, and QVM's,
 * in api_qvm.cc.  Which one a descriptor belongs to is chosen per simulation
 * by the "qemu" parameter of KvmVM and BaseKvmCPU, so both may be compiled
 * into one binary; @p qemu below selects between them on every call.
 *
 * Keeping this behind a handful of functions is what stops base.cc and vm.cc
 * from having to know about either backend, or to include the host headers
 * that go with them.
 */
namespace kvm_api
{

/** Whether the backend selected by @p qemu was compiled into this binary. */
bool available(bool qemu);

/** Human-readable name of the backend, for diagnostics. */
const char *name(bool qemu);

/** Open the KVM system descriptor (/dev/kvm, or QVM's stand-in for it). */
int open(bool qemu);

/** Release a descriptor obtained from open(), or from a KVM_CREATE_* call. */
int close(bool qemu, int fd);

/** Issue a KVM request.  @p request is a KVM_* number from <linux/kvm.h>. */
int ioctl(bool qemu, int fd, int request, long p1);

/**
 * Map a vCPU's shared communication area, which is the only mapping gem5
 * makes on a KVM descriptor.  @p len comes from KVM_GET_VCPU_MMAP_SIZE.
 * Returns nullptr on error -- not MAP_FAILED, so that callers need no
 * <sys/mman.h> of their own.
 */
void *mmap(bool qemu, int fd, size_t len);

/** Undo mmap(). */
int munmap(bool qemu, void *addr, size_t len);

} // namespace kvm_api

} // namespace gem5
