// RESEARCH ONLY -- NOT PRODUCTION. See ../README.md and plan.md 8.1/8.3/8.4.
//
// Carrier-gate probe (research/decisions.md ESC-05; pre-registration
// research/evidence/CARRIER-01/): register ONE one-shot POD callback on the
// Unreal GameThread through the *sanctioned* FTSTicker scheduler, using a
// LEGITIMATE TFunction constructed from genuine UE 5.4.4 headers with MSVC
// 14.38 -- no vtable/.text patch, no HW breakpoint, no hand-copied ABI.
//
// Path (all game-side addresses resolved by the controller, fingerprint-gated,
// clean provenance -- research/evidence/CARRIER-01/derived-addresses.json):
//   GetCoreTicker() -> FTSTicker&              (RVA 0xf53370)
//   FTSTicker::AddTicker(name, 0, TFunction)   (RVA 0xf4ded0, member+sret ABI)
//     the game builds an FElement, enqueues to a TMpscQueue (thread-safe from
//     any thread), returns a TWeakPtr<FElement> (16-byte sret we release).
//   -> our callback fires on the GameThread when the ticker drains the queue,
//      records POD (marker, thread id, count), returns false = one-shot
//      self-unregister.
//
// ALLOCATOR BOUNDARY: our TFunction<bool(float)> from a captureless callable is
// 32-byte INLINE (NUM_TFUNCTION_INLINE_BYTES=32 engine default), so no heap.
// The only FMemory symbol our compiled owned-object code references
// (TFunction_CopyableOwnedObject::CloneToEmptyStorage) is FMemory::Malloc; we
// DEFINE it here forwarding to the game's FMemory::Malloc so any allocation is
// game-allocator-consistent (the game heap-owns/frees the FElement itself).
//
// The callback runs on the GameThread (which predates our DLL load, so no
// DLL_THREAD_ATTACH ran for it): it is strictly TLS-free -- reads the current
// thread id + POD stores only, no allocation (the P-02/GT-01 lesson). We use
// UE's own FPlatformTLS/FPlatformAtomics (not <windows.h>) to keep the ABI in
// UE's world and avoid the TEXT-macro clash.

#include "Containers/Ticker.h"
#include "HAL/PlatformTLS.h"
#include "HAL/PlatformAtomics.h"
#include <cstdint>

// ---- game-side function ABIs (resolved addresses handed in by controller) ----
using GetCoreTickerFn = void* (*)();  // returns FTSTicker& in RAX
// AddTicker is a member fn returning a 16-byte TWeakPtr by sret. Replicated as a
// raw call: RCX=this, RDX=&sret, R8=name, XMM3=delay(float), [stack]=&TFunction.
// TFunction (non-trivial) is passed BY HIDDEN POINTER on x64, so the 5th param
// is a pointer to our TFunction, matching the game's own call site.
using AddTickerRaw = void(__fastcall*)(void* thisTicker, void* sretHandle,
                                       const wchar_t* name, float delay, void* fnPtr);
using MallocFn = void* (*)(size_t Count, uint32_t Alignment);

namespace {
constexpr uint64_t kFtsMagic = 0x4950502D46545354ULL;  // "IPP-FTST"
constexpr uint32_t kProto = 1;
constexpr uint32_t kMarkerFired = 0x46495245u;  // "FIRE"

#pragma pack(push, 1)
struct FtsProbeIo {
    uint64_t magic;
    uint32_t protocol_version;
    uint32_t registered_ok;    // worker sets 1 after AddTicker returns
    uint64_t add_ticker;       // game RVA-resolved VAs (input)
    uint64_t get_core_ticker;
    uint64_t fmemory_malloc;
    uint32_t marker;           // callback sets kMarkerFired (output, GameThread)
    uint32_t callback_tid;     // current thread id in the callback
    uint32_t callback_count;   // interlocked; expected 1
    uint32_t worker_tid;       // the injected thread that called AddTicker
    uint64_t reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(FtsProbeIo) == 72, "FtsProbeIo layout must match the controller");

static FtsProbeIo* volatile g_io = nullptr;
static MallocFn g_game_malloc = nullptr;

// One-shot POD callback -- runs on the GameThread. STRICTLY TLS-free.
bool ProbeCallback(float /*DeltaTime*/) {
    FtsProbeIo* io = g_io;
    if (io != nullptr) {
        io->callback_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
        FPlatformAtomics::InterlockedIncrement(reinterpret_cast<volatile int32*>(&io->callback_count));
        io->marker = kMarkerFired;
    }
    return false;  // one-shot: do not reschedule; ticker self-removes the element
}

// stand-in for the private FTSTicker::FElement; TWeakPtr's ctor/dtor are
// type-independent (they only touch the reference controller), so this releases
// the weak reference AddTicker returns without a leak.
struct FTickerElementOpaque;
}  // namespace

// The one FMemory symbol our owned-object code references. Forward to the game's
// allocator so any allocation is game-consistent. Never resolves to the CRT heap.
void* FMemory::Malloc(SIZE_T Count, uint32 Alignment) {
    return g_game_malloc(static_cast<size_t>(Count), static_cast<uint32_t>(Alignment));
}

extern "C" __declspec(dllexport) unsigned long Init(void* lpParam) {
    FtsProbeIo* io = reinterpret_cast<FtsProbeIo*>(lpParam);
    if (io == nullptr || io->magic != kFtsMagic || io->protocol_version != kProto) {
        return 0xFFFFFFFFu;
    }
    if (io->add_ticker == 0 || io->get_core_ticker == 0 || io->fmemory_malloc == 0) {
        return 0xFFFFFFFEu;
    }
    g_game_malloc = reinterpret_cast<MallocFn>(static_cast<uintptr_t>(io->fmemory_malloc));
    g_io = io;
    return 0u;
}

// CreateRemoteThread entry: register ONE ticker. Safe from this injected thread
// (AddTicker enqueues to a TMpscQueue). The callback fires later on the GameThread.
extern "C" __declspec(dllexport) unsigned long RegisterTicker(void* lpParam) {
    FtsProbeIo* io = reinterpret_cast<FtsProbeIo*>(lpParam);
    if (io == nullptr || io != g_io) {
        return 0xFFFFFFFFu;
    }
    io->worker_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());

    auto get_core_ticker =
        reinterpret_cast<GetCoreTickerFn>(static_cast<uintptr_t>(io->get_core_ticker));
    auto add_ticker =
        reinterpret_cast<AddTickerRaw>(static_cast<uintptr_t>(io->add_ticker));

    void* ticker = get_core_ticker();  // &TheTicker
    if (ticker == nullptr) {
        return 0xFFFFFFFDu;
    }

    // Legitimate inline TFunction<bool(float)> from a captureless callable.
    TFunction<bool(float)> fn = &ProbeCallback;

    // 16-byte TWeakPtr<FElement> sret buffer; released on scope exit.
    TWeakPtr<FTickerElementOpaque> handle;

    add_ticker(ticker, &handle, L"MiseryCarrierProbe", 0.0f, &fn);
    io->registered_ok = 1u;
    // handle (weak) and fn (inline) destruct here: weak-ref release, no free.
    return 0u;
}
