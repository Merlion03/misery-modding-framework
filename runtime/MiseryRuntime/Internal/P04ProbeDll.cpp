// P-04 probe -- executes EXACTLY the pre-registered chain
// (research/evidence/P-04/preregistration.md) and nothing else.
//
//   Misery::GameThread::Enqueue -> GameThread
//     -> build fixed-buffer, game-FMemory-backed FString   (gate D3)
//     -> ProcessEvent(CDO, MakeSoftObjectPath, P1)          (reflected)
//     -> ProcessEvent(CDO, LoadAsset_Blocking,  P2)         (reflected)
//     -> record the returned UObject* (POD read only)
//     -> FMemory::Free(FString buffer) + zero its fields
//
// Then the identical chain once more for the pre-registered negative control.
// No inventory, no registration, no spawning, no Blueprint gameplay, no DataTable
// mutation, no native LoadPackage, no hooks. All inspection of the result is left
// to the read-only controller; this file only records POD.
#include <atomic>
#include <cstdint>

#include "GameThreadDispatcher.h"
#include "UE54TickerCarrier.h"
#include "../Public/MiseryGameThread.h"
#include "Containers/UnrealString.h"
#include "HAL/PlatformTLS.h"

using Misery::Internal::CarrierBindings;
using Misery::Internal::GameThreadDispatcher;
using Misery::Internal::IGameThreadCarrier;

// FString/TArray field offsets -- forced by the genuine UE declarations
// (Array.h:3231-3233; sizes 8+4+4 sum exactly to sizeof==16, so no padding).
static_assert(sizeof(FString) == 16, "FString must be 16 bytes");
static_assert(sizeof(void*) + sizeof(int32) + sizeof(int32) == sizeof(FString),
              "no padding => offsets forced");
static constexpr int OFF_DATA = 0, OFF_NUM = 8, OFF_MAX = 12;

using ProcessEventFn = void(__fastcall*)(void* obj, void* func, void* parms);
using MallocFn = void* (*)(size_t, uint32_t);
using FreeFn = void(__fastcall*)(void* fmalloc, void* ptr);

namespace {

constexpr uint64_t kMagic = 0x4950502D50303400ULL;  // "IPP-P04\0"
constexpr uint32_t kProto = 1;
constexpr int kPathMax = 128;

#pragma pack(push, 1)
struct CallRecord {
    uint32_t ran;
    uint32_t callback_tid;
    // FString self-check before the call
    uint32_t fstring_len;       // Len() via genuine inline API
    uint32_t fstring_ok;        // content + terminator + slack all correct
    uint64_t fstring_buffer;    // the game-allocated buffer we own
    // FSoftObjectPath the engine produced (P1+16): FTopLevelAssetPath + FString
    uint32_t pkg_cmp_index, pkg_number;
    uint32_t asset_cmp_index, asset_number;
    uint64_t subpath_data;      // must stay 0 (empty SubPathString)
    uint32_t subpath_num, subpath_max;
    // result
    uint64_t returned_object;
    uint32_t freed;             // buffer freed + fields zeroed
    uint32_t reserved;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct P04Io {
    uint64_t magic;
    uint32_t proto;
    uint32_t max_jobs_per_tick;
    // carrier
    uint64_t add_ticker, get_core_ticker, fmemory_malloc;
    uint8_t sig_add[16], sig_get[16], sig_malloc[16];
    // allocator free (GMalloc vtable slot 9)
    uint64_t gmalloc_ptr_va;
    uint32_t free_slot_disp;
    uint32_t pad0;
    // reflected targets
    uint64_t cdo, process_event, fn_make_soft_object_path, fn_load_asset_blocking;
    // inputs (UTF-16, NUL-terminated, supplied by the controller)
    uint16_t target_path[kPathMax];
    uint16_t negative_path[kPathMax];
    // lifecycle outputs
    uint32_t activated, initialized, state, wait_stopped_ok;
    // per-call outputs
    CallRecord positive;
    CallRecord negative;
};
#pragma pack(pop)

P04Io* g_io = nullptr;
GameThreadDispatcher* g_disp = nullptr;
IGameThreadCarrier* g_carrier = nullptr;
MallocFn g_malloc = nullptr;
std::atomic<uint32_t> g_jobs_done{0};

void GameFree(void* p) {
    if (!p || !g_io) return;
    void* fmalloc = *reinterpret_cast<void**>(static_cast<uintptr_t>(g_io->gmalloc_ptr_va));
    if (!fmalloc) return;
    void** vt = *reinterpret_cast<void***>(fmalloc);
    auto fn = reinterpret_cast<FreeFn>(vt[g_io->free_slot_disp / 8]);
    fn(fmalloc, p);
}

int PathLen(const uint16_t* s) { int n = 0; while (s[n]) ++n; return n; }

// One pre-registered pass. `path` is UTF-16 NUL-terminated; rec receives POD only.
void RunOnePass(const uint16_t* path, CallRecord* rec) {
    rec->callback_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());

    alignas(8) unsigned char p1[48] = {};
    alignas(8) unsigned char p2[48] = {};

    // ---- gate-D3 fixed-buffer FString, backed by the GAME allocator ----
    const int len = PathLen(path);
    const size_t bytes = static_cast<size_t>(len + 1) * sizeof(TCHAR);
    TCHAR* buf = static_cast<TCHAR*>(g_malloc(bytes, 0u /* DEFAULT_ALIGNMENT */));
    if (!buf) { rec->ran = 2; return; }
    for (int i = 0; i < len; ++i) buf[i] = static_cast<TCHAR>(path[i]);
    buf[len] = TEXT('\0');
    *reinterpret_cast<void**>(p1 + OFF_DATA) = buf;
    *reinterpret_cast<int32*>(p1 + OFF_NUM) = len + 1;
    *reinterpret_cast<int32*>(p1 + OFF_MAX) = len + 1;
    rec->fstring_buffer = reinterpret_cast<uint64_t>(buf);

    // self-check through UE's own FORCEINLINE accessors
    const FString& s = *reinterpret_cast<const FString*>(p1);
    const TCHAR* data = *s;
    uint32_t ok = (s.Len() == len) && !s.IsEmpty() && data[len] == TEXT('\0');
    for (int i = 0; ok && i < len; ++i) if (data[i] != static_cast<TCHAR>(path[i])) ok = 0;
    rec->fstring_len = static_cast<uint32_t>(s.Len());
    rec->fstring_ok = ok;
    if (!ok) { GameFree(buf); rec->ran = 3; return; }

    auto process_event = reinterpret_cast<ProcessEventFn>(
        static_cast<uintptr_t>(g_io->process_event));
    void* cdo = reinterpret_cast<void*>(static_cast<uintptr_t>(g_io->cdo));

    // ---- reflected MakeSoftObjectPath: FString@0 -> FSoftObjectPath@16 ----
    process_event(cdo, reinterpret_cast<void*>(
        static_cast<uintptr_t>(g_io->fn_make_soft_object_path)), p1);

    // FSoftObjectPath = FTopLevelAssetPath{FName PackageName; FName AssetName;} + FString SubPathString
    rec->pkg_cmp_index   = *reinterpret_cast<uint32_t*>(p1 + 16 + 0);
    rec->pkg_number      = *reinterpret_cast<uint32_t*>(p1 + 16 + 4);
    rec->asset_cmp_index = *reinterpret_cast<uint32_t*>(p1 + 16 + 8);
    rec->asset_number    = *reinterpret_cast<uint32_t*>(p1 + 16 + 12);
    rec->subpath_data    = *reinterpret_cast<uint64_t*>(p1 + 16 + 16);
    rec->subpath_num     = *reinterpret_cast<uint32_t*>(p1 + 16 + 24);
    rec->subpath_max     = *reinterpret_cast<uint32_t*>(p1 + 16 + 28);

    // ---- reflected LoadAsset_Blocking: FSoftObjectPtr@0 -> UObject*@40 ----
    // FSoftObjectPtr = { FWeakObjectPtr WeakPtr@0 (8); FSoftObjectPath ObjectID@8 (32) }
    for (int i = 0; i < 32; ++i) p2[8 + i] = p1[16 + i];   // copy the path, never interpret it
    process_event(cdo, reinterpret_cast<void*>(
        static_cast<uintptr_t>(g_io->fn_load_asset_blocking)), p2);
    rec->returned_object = *reinterpret_cast<uint64_t*>(p2 + 40);

    // ---- release the caller-owned input buffer (gate D2: ProcessEvent never destroys parms) ----
    GameFree(buf);
    *reinterpret_cast<void**>(p1 + OFF_DATA) = nullptr;
    *reinterpret_cast<int32*>(p1 + OFF_NUM) = 0;
    *reinterpret_cast<int32*>(p1 + OFF_MAX) = 0;
    rec->freed = 1;
    rec->ran = 1;
}

void JobPositive(void*) { RunOnePass(g_io->target_path, &g_io->positive); g_jobs_done.fetch_add(1); }
void JobNegative(void*) { RunOnePass(g_io->negative_path, &g_io->negative); g_jobs_done.fetch_add(1); }

}  // namespace

namespace Misery { namespace GameThread {
bool IsAvailable() { return g_disp && g_disp->stats().state.load() == GameThreadDispatcher::kRunning; }
bool Enqueue(JobFn fn, void* ctx) { return g_disp && g_disp->Enqueue(fn, ctx); }
}}

extern "C" __declspec(dllexport) unsigned long Init(void* param) {
    P04Io* io = static_cast<P04Io*>(param);
    if (!io || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
    if (!io->add_ticker || !io->get_core_ticker || !io->fmemory_malloc) return 0xFFFFFFFEu;
    if (!io->cdo || !io->process_event || !io->fn_make_soft_object_path ||
        !io->fn_load_asset_blocking || !io->gmalloc_ptr_va) return 0xFFFFFFFDu;
    g_io = io;
    g_malloc = reinterpret_cast<MallocFn>(static_cast<uintptr_t>(io->fmemory_malloc));

    CarrierBindings b;
    b.add_ticker = io->add_ticker; b.get_core_ticker = io->get_core_ticker;
    b.fmemory_malloc = io->fmemory_malloc;
    for (int i = 0; i < 16; ++i) { b.sig_add[i]=io->sig_add[i]; b.sig_get[i]=io->sig_get[i]; b.sig_malloc[i]=io->sig_malloc[i]; }
    g_carrier = Misery::Internal::CreateUE54TickerCarrier(b);
    g_disp = new GameThreadDispatcher();
    GameThreadDispatcher::Config cfg;
    cfg.max_jobs_per_tick = io->max_jobs_per_tick ? io->max_jobs_per_tick : 8;
    const bool ok = g_disp->Initialize(g_carrier, cfg);
    io->activated = ok ? 1u : 0u;
    io->initialized = ok ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    return ok ? 0u : 0xFFFFFFFCu;
}

// Enqueue the pre-registered positive pass, then the negative control.
extern "C" __declspec(dllexport) unsigned long RunPositive(void* param) {
    P04Io* io = static_cast<P04Io*>(param);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    return Misery::GameThread::Enqueue(&JobPositive, nullptr) ? 0u : 1u;
}
extern "C" __declspec(dllexport) unsigned long RunNegative(void* param) {
    P04Io* io = static_cast<P04Io*>(param);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    return Misery::GameThread::Enqueue(&JobNegative, nullptr) ? 0u : 1u;
}

extern "C" __declspec(dllexport) unsigned long Shutdown(void* param) {
    P04Io* io = static_cast<P04Io*>(param);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    g_disp->Shutdown(5000);
    io->wait_stopped_ok = g_disp->wait_stopped_ok() ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    delete g_disp; g_disp = nullptr;
    Misery::Internal::DestroyCarrier(g_carrier); g_carrier = nullptr;
    return 0u;
}
