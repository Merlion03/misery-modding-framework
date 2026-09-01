// RESEARCH ONLY -- NOT PRODUCTION. See ../README.md and plan.md 8.1/8.3/8.4.
//
// Single-purpose research probe: make the live game perform ONE real level
// transition, so that the production Stage 5B runtime can be observed detecting
// and surviving it.
//
// WHAT THIS PROBE DOES, AND THE LINE IT DOES NOT CROSS
// ----------------------------------------------------
// It CAUSES the transition. It does nothing else.
//
//   causes         this probe          one ProcessEvent call, no arguments
//   detects        MiseryRuntime       revokes the generation
//   refuses        MiseryRuntime       stale anchors cannot be acquired
//   resolves       MiseryRuntime       new anchors, new generation
//   reapplies      MiseryRuntime       the mod's existing declaration
//
// That separation is the whole point of the exercise, so it is enforced by what
// this file is capable of rather than by intention: there is no code here that
// reads or writes an anchor, touches a DataTable, calls the items backend, or
// knows a content generation exists. It cannot help the production path pass.
// Its total effect on the process is one call to a reflected function that the
// game itself exposes.
//
// WHY RestartLevel
// ----------------
// APlayerController::RestartLevel is a zero-parameter UFunction -- MEASURED on
// this build as num_parms 0, ParmsSize 0 (stage5b_find_transition). A call with
// no parameter block cannot get a parameter block wrong: no offsets to derive,
// no FName or FString to marshal, nothing to leak. Every other candidate this
// build exposes (OpenLevel, ClientTravel, ServerTravel, LoadStreamLevel) takes
// three to five parameters and would need its layout derived correctly before
// the transition could even be attempted.
//
// It is also the game's own mechanism rather than something synthesised: it is
// the engine's standard level restart, reached through the same reflected-call
// path the game uses for every other Blueprint-visible function.
//
// HOW IT REACHES THE GAME THREAD
// ------------------------------
// The same carrier the rest of this project uses, and for the same reason:
// ProcessEvent must be called on the game thread. The controller resolves
// FTSTicker::GetCoreTicker and AddTicker, this registers ONE one-shot callback,
// and the callback makes the call and returns false so the ticker removes it.
// No hooks, no detours, no patched bytes, no hardware breakpoints.
#include "Containers/Ticker.h"
#include "HAL/PlatformTLS.h"
#include "HAL/PlatformAtomics.h"

#include <cstdint>

using GetCoreTickerFn = void* (*)();
// See probe_ftsticker.cpp: TFunction is non-trivial, so on x64 it is passed by
// hidden pointer, and the sret TWeakPtr comes back in RDX. This matches the
// game's own call site.
using AddTickerRaw = void(__fastcall*)(void* thisTicker, void* sretHandle,
                                       const wchar_t* name, float delay,
                                       void* fnPtr);
using MallocFn = void* (*)(size_t Count, uint32_t Alignment);
// UObject::ProcessEvent(UFunction*, void* Parms).
using ProcessEventFn = void(__fastcall*)(void* self, void* function,
                                         void* parms);

namespace {

constexpr uint64_t kMagic = 0x4950502D5452414EULL;   // "IPP-TRAN"
constexpr uint32_t kProto = 1;

#pragma pack(push, 1)
struct TransitionIo {
    // ---- input, written by the controller before Init ----
    uint64_t magic;
    uint32_t protocol_version;
    uint32_t reserved0;
    uint64_t add_ticker;
    uint64_t get_core_ticker;
    uint64_t fmemory_malloc;
    uint64_t process_event;      // UObject::ProcessEvent
    uint64_t target;             // the live PlayerController
    uint64_t function;           // its RestartLevel UFunction
    // ---- output ----
    uint32_t registered_ok;      // AddTicker returned on the injected thread
    uint32_t worker_tid;
    uint32_t called;             // 1 once the callback has made the call
    uint32_t callback_tid;       // the game thread, as measured here
    uint32_t callback_count;     // interlocked; expected exactly 1
    uint32_t reserved1;
    uint64_t reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(TransitionIo) == 104,
              "TransitionIo layout must match the controller");

TransitionIo* volatile g_io = nullptr;
MallocFn g_game_malloc = nullptr;

// Runs on the game thread. One call, then never again.
//
// The IO fields are written BEFORE the call, because the call does not return
// in any ordinary sense of the word -- it begins tearing the world down, and
// whatever it does to this thread's stack afterwards must not decide whether
// the controller can see that the probe fired.
bool TransitionCallback(float /*DeltaTime*/) {
    TransitionIo* io = g_io;
    if (io == nullptr || io->called != 0u) {
        return false;
    }
    io->callback_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    FPlatformAtomics::InterlockedIncrement(
        reinterpret_cast<volatile int32*>(&io->callback_count));
    io->called = 1u;

    auto process_event =
        reinterpret_cast<ProcessEventFn>(static_cast<uintptr_t>(io->process_event));
    process_event(reinterpret_cast<void*>(static_cast<uintptr_t>(io->target)),
                  reinterpret_cast<void*>(static_cast<uintptr_t>(io->function)),
                  nullptr);   // ParmsSize 0: there is no parameter block
    return false;             // one-shot
}

struct FTickerElementOpaque;

}  // namespace

// The one FMemory symbol the owned-object code references. Forwarded to the
// game's allocator so nothing ever reaches the CRT heap.
void* FMemory::Malloc(SIZE_T Count, uint32 Alignment) {
    return g_game_malloc(static_cast<size_t>(Count),
                         static_cast<uint32_t>(Alignment));
}

extern "C" __declspec(dllexport) unsigned long Init(void* lpParam) {
    TransitionIo* io = reinterpret_cast<TransitionIo*>(lpParam);
    if (io == nullptr || io->magic != kMagic || io->protocol_version != kProto) {
        return 0xFFFFFFFFu;
    }
    if (io->add_ticker == 0 || io->get_core_ticker == 0 ||
        io->fmemory_malloc == 0 || io->process_event == 0 ||
        io->target == 0 || io->function == 0) {
        return 0xFFFFFFFEu;
    }
    g_game_malloc =
        reinterpret_cast<MallocFn>(static_cast<uintptr_t>(io->fmemory_malloc));
    g_io = io;
    return 0u;
}

// CreateRemoteThread entry. Registering from this injected thread is safe --
// AddTicker enqueues to a TMpscQueue -- and the callback fires later on the
// game thread.
extern "C" __declspec(dllexport) unsigned long Fire(void* lpParam) {
    TransitionIo* io = reinterpret_cast<TransitionIo*>(lpParam);
    if (io == nullptr || io != g_io) {
        return 0xFFFFFFFFu;
    }
    io->worker_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());

    auto get_core_ticker = reinterpret_cast<GetCoreTickerFn>(
        static_cast<uintptr_t>(io->get_core_ticker));
    auto add_ticker =
        reinterpret_cast<AddTickerRaw>(static_cast<uintptr_t>(io->add_ticker));

    void* ticker = get_core_ticker();
    if (ticker == nullptr) {
        return 0xFFFFFFFDu;
    }
    TFunction<bool(float)> fn = &TransitionCallback;
    TWeakPtr<FTickerElementOpaque> handle;
    add_ticker(ticker, &handle, L"MiseryTransitionProbe", 0.0f, &fn);
    io->registered_ok = 1u;
    return 0u;
}
