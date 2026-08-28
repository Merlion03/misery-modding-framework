// RESEARCH ONLY -- NOT PRODUCTION. See ../README.md and plan.md 8.1/8.3/8.4.
//
// Single-purpose research probe (capability GT-01, escalation ESC-03,
// research/decisions.md; pre-registration research/evidence/GT-01/
// preregistration.md): proves that ONE callback of ours can execute on the
// Unreal GameThread of the live MISERY-Win64-Shipping.exe, initiated from an
// injected thread, recording only POD, doing NO UObject/ProcessEvent/load work,
// then removing every trace.
//
// MECHANISM. The controller arms an EXECUTE hardware breakpoint (debug register
// Dr0) on the verified address of UObject::ProcessEvent (RVA 0x12AC1F0, three
// agreeing derivations -- LOG-0072), on the GameThread ONLY (debug registers are
// per-thread state, so no other thread can trap). This file provides the
// Vectored Exception Handler that catches the resulting #DB (delivered as
// EXCEPTION_SINGLE_STEP) on the GameThread, records POD, CLEARS Dr0/Dr7 in the
// delivered ContextRecord so the breakpoint is one-shot, and returns
// EXCEPTION_CONTINUE_EXECUTION. Zero bytes of engine code or data are modified;
// an execute HW breakpoint is CPU state, not a code patch, so ProcessEvent's
// bytes are never touched.
//
// This file contains NO address knowledge of its own: the trap address, the
// armed GameThread id, and the .text bounds are all resolved by the controller
// and handed in via GtProbeIo. It only reacts to the exact breakpoint the
// controller arms.
//
// PROCESS-WIDE VEH DISCIPLINE (the P-02 probe's hard-won lesson,
// ../probe/probe.cpp lines 33-58): AddVectoredExceptionHandler is process-wide,
// and this is a heavily multithreaded live UE5 process. This handler therefore
// does the ABSOLUTE MINIMUM gate before touching anything: it acts ONLY when the
// exception is EXCEPTION_SINGLE_STEP AND the Dr0 condition bit is set in Dr6 AND
// the faulting Rip equals the controller-supplied trap address. For every other
// exception on every other thread it returns EXCEPTION_CONTINUE_SEARCH untouched
// and immediately. It never longjmps and never mutates any thread's context
// except to clear the debug registers it is responsible for.
//
// No thread_local anywhere (the P-02 rehearsal proved implicit TLS is unreliable
// for a DLL loaded late via LoadLibraryW). All state is a plain static pointer
// to the controller-owned GtProbeIo page; the handler and the init/self-test
// entry points are the only readers/writers, and they interlock on io->fired.

#include <windows.h>
#include <cstdint>

namespace {

constexpr uint64_t kGtProbeMagic = 0x4950502D47543031ULL;  // "IPP-GT01"
constexpr uint32_t kProtocolVersion = 1;

#pragma pack(push, 1)
struct GtProbeIo {
    // --- input: written by the controller before Init ---
    uint64_t magic;
    uint32_t protocol_version;
    uint32_t armed_tid;        // GameThread id the controller armed Dr0 on
    uint64_t trap_addr;        // == &UObject::ProcessEvent (live VA)
    uint64_t text_lo;          // MISERY .text VA low bound  (return-addr provenance)
    uint64_t text_hi;          // MISERY .text VA high bound
    // --- output: trap record, written by the VEH handler on the GameThread ---
    uint32_t hit_count;        // interlocked; expected exactly 1
    uint32_t hit_tid;          // GetCurrentThreadId() at the trap
    uint64_t hit_rip;          // faulting Rip (expected == trap_addr)
    uint64_t hit_return_addr;  // [Rsp] at function-entry #DB == caller return addr
    uint64_t hit_qpc;          // QueryPerformanceCounter at the trap
    uint32_t hit_return_in_text; // 1 if hit_return_addr in [text_lo,text_hi)
    uint32_t fired;            // interlocked one-shot election
    // --- output: negative-control N1, written by RunSelfTest on the injected thread ---
    uint32_t self_tid;
    uint64_t self_rsp;
    uint64_t self_return_addr;
    uint32_t self_done;
    // --- status ---
    uint32_t veh_installed;    // 1 after Init registers the VEH
    uint32_t teardown_done;    // 1 after Teardown removes the VEH
    uint8_t  reserved[4];
};
#pragma pack(pop)

static_assert(sizeof(GtProbeIo) == 116, "GtProbeIo layout must match the controller's struct format");

static GtProbeIo* volatile g_io = nullptr;
static PVOID g_veh = nullptr;

// Dr6 bit 0 (B0) is set when the Dr0 breakpoint condition was detected.
constexpr uint64_t kDr6_B0 = 0x1ULL;

LONG WINAPI GtVehHandler(PEXCEPTION_POINTERS info) {
    GtProbeIo* io = g_io;
    if (io == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // Minimal, specific gate -- see the process-wide VEH discipline note above.
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    CONTEXT* ctx = info->ContextRecord;
    if ((ctx->Dr6 & kDr6_B0) == 0) {
        return EXCEPTION_CONTINUE_SEARCH;   // a #DB, but not from our Dr0
    }
    if (ctx->Rip != io->trap_addr) {
        return EXCEPTION_CONTINUE_SEARCH;   // not our breakpoint
    }

    // This is our one breakpoint firing. Elect exactly one recorder.
    LONG* const p_fired = reinterpret_cast<LONG*>(&io->fired);
    LONG* const p_count = reinterpret_cast<LONG*>(&io->hit_count);
    if (InterlockedCompareExchange(p_fired, 1, 0) != 0) {
        // A second entrant before the cleared Dr0 loaded: still clear and count.
        InterlockedIncrement(p_count);
        ctx->Dr0 = 0; ctx->Dr7 = 0; ctx->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    const uint32_t tid = GetCurrentThreadId();
    // At an execute #DB on a function's first byte, [Rsp] is the return address
    // pushed by the CALL. Rsp is valid here (we are at a real function entry).
    const uint64_t ret = *reinterpret_cast<uint64_t*>(ctx->Rsp);
    LARGE_INTEGER qpc; qpc.QuadPart = 0;
    QueryPerformanceCounter(&qpc);

    io->hit_tid = tid;
    io->hit_rip = ctx->Rip;
    io->hit_return_addr = ret;
    io->hit_return_in_text = (ret >= io->text_lo && ret < io->text_hi) ? 1u : 0u;
    io->hit_qpc = static_cast<uint64_t>(qpc.QuadPart);
    InterlockedIncrement(p_count);

    // One-shot: clear the debug registers we own so the breakpoint does not
    // re-arm when this cleared context is loaded on return. N2 guarantees the
    // game had all debug registers zero before arming, so zeroing restores the
    // exact prior state.
    ctx->Dr0 = 0; ctx->Dr7 = 0; ctx->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

}  // namespace

// CreateRemoteThread entry: register the VEH. Called by the controller AFTER the
// page is populated and BEFORE Dr0 is armed, so the handler is always in place
// before any trap can occur.
extern "C" __declspec(dllexport) DWORD WINAPI Init(LPVOID lpParam) {
    GtProbeIo* io = reinterpret_cast<GtProbeIo*>(lpParam);
    if (io == nullptr || io->magic != kGtProbeMagic ||
        io->protocol_version != kProtocolVersion) {
        return 0xFFFFFFFFu;
    }
    g_io = io;
    g_veh = AddVectoredExceptionHandler(1, GtVehHandler);  // 1 = first
    if (g_veh == nullptr) {
        return 0xFFFFFFFEu;
    }
    io->veh_installed = 1u;
    return 0u;
}

// CreateRemoteThread entry: negative control N1. Runs the identical recorder
// directly on THIS injected thread (no trap) and stores its identity. If this
// cannot be distinguished from the GameThread record, the instrument is invalid.
extern "C" __declspec(dllexport) DWORD WINAPI RunSelfTest(LPVOID lpParam) {
    GtProbeIo* io = reinterpret_cast<GtProbeIo*>(lpParam);
    if (io == nullptr || io->magic != kGtProbeMagic) {
        return 0xFFFFFFFFu;
    }
    io->self_tid = GetCurrentThreadId();
    uint64_t rsp = 0;
#if defined(__GNUC__)
    __asm__ __volatile__("movq %%rsp, %0" : "=r"(rsp));
#endif
    io->self_rsp = rsp;
    io->self_return_addr = reinterpret_cast<uint64_t>(__builtin_return_address(0));
    io->self_done = 1u;
    return 0u;
}

// CreateRemoteThread entry: remove the VEH once the controller has confirmed no
// trap can re-enter (Dr0 cleared). After this returns, FreeLibrary is safe: no
// engine thread holds a pointer into this DLL.
extern "C" __declspec(dllexport) DWORD WINAPI Teardown(LPVOID lpParam) {
    GtProbeIo* io = reinterpret_cast<GtProbeIo*>(lpParam);
    if (g_veh != nullptr) {
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = nullptr;
    }
    g_io = nullptr;
    if (io != nullptr && io->magic == kGtProbeMagic) {
        io->teardown_done = 1u;
    }
    return 0u;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    (void)reason;
    return TRUE;
}
