// RESEARCH ONLY -- NOT PRODUCTION. See ../README.md and plan.md 8.1/8.3.
//
// Single-purpose, single-call research probe (capability P-02, plan.md 8.3):
// loaded into the MISERY-Win64-Shipping.exe process by ipp_controller.py,
// makes EXACTLY ONE UFunction call through ProcessEvent, reports the result,
// and is unloaded again in the same session. Not a generic invoker: the
// UObject/UFunction/ProcessEvent pointers this reads are resolved entirely
// by the controller (reusing research/instruments/eri/eri.py's own already-
// tested I-02..I-05 discovery code) and handed in via IppProbeIo -- this
// file contains no address/offset knowledge of MISERY's own class layout at
// all, only the already-confirmed ProcessEvent ABI contract from
// research/RESEARCH_LOG.md LOG-0056/LOG-0057 (Parms buffer exactly
// Function->ParmsSize bytes, ReturnValueOffset into that same buffer) and
// ONE additional, already-established offset it reads defensively at call
// time (UFunction::ParmsSize at +0xB6, eri.py's own UFUNCTION_PARMS_SIZE_OFFSET
// -- see the cross-check in RunProbe below).
//
// Crash containment: MinGW-w64 g++ does not support the MSVC __try/__except
// keywords (verified empirically this session -- neither plain nor with
// -fms-extensions), so the one indirect call this file ever makes is guarded
// by a Vectored Exception Handler that longjmp()s back out on a hardware
// exception, rehearsed end-to-end via CreateRemoteThread against a real
// separate process before this file was ever pointed at the game. All
// shared state for that guard is a plain (non-thread_local) static: this
// probe's own rehearsal found that this DLL is loaded late, via
// CreateRemoteThread -> LoadLibraryW rather than being present at process
// start, and Windows' implicit TLS support for a __declspec(thread)/
// thread_local variable in a DLL loaded that way is unreliable -- using it
// here silently corrupted the exception guard itself. Nothing in this file
// is ever called from more than one thread, so a plain static is correct,
// not merely a workaround.
//
// CROSS-THREAD SAFETY (adversarial review finding, fixed before first live
// run): AddVectoredExceptionHandler installs its callback PROCESS-WIDE, not
// per-thread. MISERY-Win64-Shipping.exe is a live, heavily multithreaded UE5
// process (render/RHI/audio/task-graph/async-loading threads, all running
// concurrently with this probe). An unrelated hardware fault on ANY of those
// OTHER threads, occurring purely by chance during the brief window this
// guard is armed, would otherwise be caught by VectoredHandler and
// longjmp() using a jmp_buf captured on THIS (the RunProbe) thread's own
// stack -- forcibly relocating the faulting thread's execution into this
// thread's stack frame while this thread is itself still physically inside
// process_event(), which never actually faulted. That is not a contained
// probe failure, it is unconditional corruption of the live game process.
// The fix: VectoredHandler additionally requires the CURRENT thread id to
// equal the id that armed the guard (captured via GetCurrentThreadId(),
// which reads the calling thread's own TEB directly and does not depend on
// this DLL's own TLS slot allocation -- the exact mechanism thread_local
// was found unreliable for above). Once that check passes, this handler is
// the only code that can legitimately be raising ANYTHING on this thread
// during this narrow window (this file's own logic between setjmp() and the
// matching io->status assignment does not itself raise), so every exception
// code is treated as fault-class here except the two a debugger might
// legitimately want to see (EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP) --
// deliberately not a hand-maintained allow-list of "known" hardware fault
// codes, which a prior draft of this file had and which an adversarial
// review found already omitted EXCEPTION_IN_PAGE_ERROR (realistic for
// UE's memory-mapped asset I/O) and the entire EXCEPTION_FLT_* family.
//
// RESIDUAL RISK, NOT FIXABLE HERE, DOCUMENTED RATHER THAN HIDDEN (from the
// same review): setjmp/longjmp performs a raw stack/register restore with
// NO C++ stack unwinding -- it invokes no destructors for any frame between
// the fault point and the setjmp() call. process_event() below is a raw
// call into real UE5.4.4 engine code, which very plausibly constructs its
// own RAII-style guards (stat/cycle-counter scopes, reentrancy-depth
// counters, script-context push/pop) on ITS OWN stack before ever reaching
// IsSteamDeck's trivial body. If a hardware fault genuinely occurs
// mid-ProcessEvent (the exact case this guard exists to survive), any such
// engine-side guard already entered will never have its release/pop/
// decrement run. This can manifest much later as a leaked lock, a tripped
// reentrancy assertion, or a deadlock -- long after this probe has
// unloaded. ipp_controller.py treats status == kStatusException as "target
// process integrity no longer guaranteed" for exactly this reason, not
// merely "the call failed" -- see its own comments. This is an inherent
// limitation of setjmp/longjmp-based recovery through opaque engine code,
// not something a different exception-code list or thread check can close.

#include <windows.h>
#include <csetjmp>
#include <cstdint>
#include <cstring>

namespace {

constexpr uint64_t kIppProbeMagic = 0x4950502D50524245ULL;  // "IPP-PRBE" (raw bytes, little-endian read back)
constexpr uint32_t kIppProtocolVersion = 1;

constexpr uint32_t kStatusNotRun = 0;
constexpr uint32_t kStatusSuccess = 1;
constexpr uint32_t kStatusException = 2;
constexpr uint32_t kStatusSanityCheckFailed = 3;
constexpr uint32_t kStatusLiveParmsSizeMismatch = 4;

// UFunction::ParmsSize, Class.h:1804 (Shipping build: UFUNCTION's own fields
// start immediately after UStruct ends at +0xB0; ParmsSize is a uint16_t at
// +0xB6, with 1 byte of padding at +0xB5 -- research/instruments/eri/eri.py's
// own UFUNCTION_PARMS_SIZE_OFFSET, already live-tested this session by I-05
// against 247/247 real functions; duplicated here as a plain numeric
// constant rather than imported, since this file has no Python runtime to
// import from -- the controller's own resolve_target() cross-checks the
// SAME live field before ever writing io->parms_size, so this is a second,
// independent read of the identical live fact, not a second offset to keep
// in sync by hand).
constexpr uintptr_t kUFunctionParmsSizeOffset = 0xB6;

#pragma pack(push, 1)
struct IppProbeIo {
    // --- input, written by the controller before RunProbe is called ---
    uint64_t magic;
    uint32_t protocol_version;
    uint64_t process_event_ptr;   // resolved ProcessEvent function pointer (CDO vtable slot 77)
    uint64_t cdo_ptr;              // resolved MiseryBlueprintFunctionLibrary CDO address
    uint64_t function_ptr;         // resolved IsSteamDeck UFunction address
    uint32_t parms_size;           // must be exactly 1 (LOG-0057) -- sanity-checked, not trusted blindly
    uint32_t return_value_offset;  // must be exactly 0 (LOG-0057) -- sanity-checked
    // --- output, written by RunProbe before it returns ---
    uint32_t status;               // kStatusNotRun/Success/Exception/SanityCheckFailed/LiveParmsSizeMismatch
    uint64_t exception_code;       // valid only when status == kStatusException
    uint8_t parms_before;          // Parms[0] immediately after zero-init, before the call
    uint8_t parms_after;           // Parms[0] immediately after the call returns
    uint8_t return_value_byte;     // Parms[return_value_offset] after the call (== parms_after here,
                                    // kept as its own field so the report does not have to assume
                                    // return_value_offset == 0 stays true if this probe is ever reused)
    uint8_t reserved;              // always 0, unused, keeps the struct a round 60 bytes
};
#pragma pack(pop)

static_assert(sizeof(IppProbeIo) == 60, "IppProbeIo must stay exactly 60 bytes -- "
              "ipp_controller.py's struct.Struct format string is hand-matched to this layout");

// Deliberately NOT thread_local -- see the file-level comment above for why.
static jmp_buf g_jump_buf;
static volatile uint64_t g_last_exception_code = 0;
static volatile bool g_guard_armed = false;
static volatile DWORD g_guard_thread_id = 0;

LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS info) {
    if (g_guard_armed && GetCurrentThreadId() == g_guard_thread_id) {
        const DWORD code = info->ExceptionRecord->ExceptionCode;
        // Leave a debugger's own breakpoint/single-step alone; treat every
        // other exception code on THIS thread during THIS narrow window as
        // fault-class (see the file-level comment for why a hand-maintained
        // allow-list of "known" hardware fault codes is deliberately not
        // used here anymore).
        if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP) {
            g_last_exception_code = code;
            g_guard_armed = false;
            longjmp(g_jump_buf, 1);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

extern "C" __declspec(dllexport) DWORD WINAPI RunProbe(LPVOID lpParam) {
    IppProbeIo* io = reinterpret_cast<IppProbeIo*>(lpParam);
    if (io == nullptr) {
        return 0xFFFFFFFFu;  // cannot even report a status -- no buffer to write into
    }

    io->status = kStatusNotRun;
    io->exception_code = 0;
    io->parms_before = 0;
    io->parms_after = 0;
    io->return_value_byte = 0;
    io->reserved = 0;

    if (io->magic != kIppProbeMagic || io->protocol_version != kIppProtocolVersion) {
        io->status = kStatusSanityCheckFailed;
        return io->status;
    }
    // The only two ABI facts this file trusts about the call it is about to
    // make (LOG-0057): both are re-checked here, redundantly with the
    // controller's own read-only check, because the controller's check and
    // this check are cheap and independent, and a mismatch here means the
    // controller resolved a DIFFERENT UFunction than the one this build was
    // written against -- refuse rather than guess.
    if (io->parms_size != 1 || io->return_value_offset != 0) {
        io->status = kStatusSanityCheckFailed;
        return io->status;
    }
    if (io->process_event_ptr == 0 || io->cdo_ptr == 0 || io->function_ptr == 0) {
        io->status = kStatusSanityCheckFailed;
        return io->status;
    }

    using ProcessEventFn = void(__fastcall*)(void* obj, void* function, void* parms);
    ProcessEventFn process_event = reinterpret_cast<ProcessEventFn>(
        static_cast<uintptr_t>(io->process_event_ptr));
    void* cdo = reinterpret_cast<void*>(static_cast<uintptr_t>(io->cdo_ptr));
    void* function = reinterpret_cast<void*>(static_cast<uintptr_t>(io->function_ptr));

    // Parms must be exactly Function->ParmsSize bytes (LOG-0056/LOG-0057,
    // ScriptCore.cpp:1971-2165) -- zero-initialised, per the same source.
    uint8_t parms[1] = {0};

    PVOID veh_handle = AddVectoredExceptionHandler(1, VectoredHandler);
    if (veh_handle == nullptr) {
        io->status = kStatusSanityCheckFailed;
        return io->status;
    }

    // Everything from here to the matching io->status assignment below is
    // one guarded region: the live ParmsSize cross-check's own dereference
    // of `function` is exactly as capable of faulting on a bad pointer as
    // process_event() itself is, so it must be inside the SAME
    // setjmp-guarded window, not performed before the guard is armed.
    if (setjmp(g_jump_buf) == 0) {
        g_guard_thread_id = GetCurrentThreadId();
        g_guard_armed = true;

        // Live cross-check (adversarial review finding, fixed before first
        // live run): io->parms_size is a copy the CONTROLLER read during
        // its own earlier discovery pass -- it is not, by itself, proof
        // that the `function` object THIS thread is about to dereference
        // still has that same ParmsSize at call time. Read the live field
        // directly out of the function object this call will actually use,
        // and refuse rather than trust a value that only arrived over the
        // wire.
        const uint16_t live_parms_size =
            *reinterpret_cast<const uint16_t*>(
                reinterpret_cast<const uint8_t*>(function) + kUFunctionParmsSizeOffset);
        if (live_parms_size != io->parms_size) {
            g_guard_armed = false;
            io->status = kStatusLiveParmsSizeMismatch;
        } else {
            io->parms_before = parms[0];
            process_event(cdo, function, parms);
            g_guard_armed = false;
            io->parms_after = parms[0];
            io->return_value_byte = parms[io->return_value_offset];
            io->status = kStatusSuccess;
        }
    } else {
        // Reached via longjmp from VectoredHandler: something in the
        // guarded region above faulted (either the live ParmsSize read or
        // the ProcessEvent call itself).
        io->exception_code = g_last_exception_code;
        io->status = kStatusException;
    }

    RemoveVectoredExceptionHandler(veh_handle);
    return io->status;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    // Deliberately does nothing beyond the default CRT behaviour on any
    // notification. All real work happens in RunProbe, called via a SECOND,
    // separate CreateRemoteThread after LoadLibraryW's own thread has
    // already returned -- never from DllMain/DLL_PROCESS_ATTACH, which
    // holds the loader lock and is not a safe place to walk the target's
    // own object graph or call into its code.
    //
    // RunProbe itself is invoked as the raw OS thread entry point of that
    // second CreateRemoteThread, bypassing any CRT thread-start trampoline.
    // This file's own logic needs nothing such a trampoline would have set
    // up (no errno/locale/new/iostream/C++ exceptions anywhere above). Left
    // genuinely open, and not resolvable from inside this file: whether
    // UE's own ProcessEvent/engine machinery implicitly assumes it is
    // running on an engine-registered thread (e.g. FPlatformTLS-backed
    // game-thread-identity or threading-model checks) that a raw
    // CreateRemoteThread-created thread never went through. Shipping builds
    // typically compile such checks out, and IsSteamDeck's own body is
    // trivial, but this is genuinely untested/unverifiable from source
    // alone -- an adversarially-reviewed, honestly-flagged residual risk of
    // the whole injection approach, not a defect this file can fix.
    (void)reason;
    return TRUE;
}
