// CR-01A probe: prove that MiseryRuntime can take real, GC-correct ownership of a
// loaded mod asset, that the asset then survives a garbage collection, and that
// releasing ownership restores normal collectability.
//
// The load reuses the already-proven P-04 chain unchanged. The ONLY new thing is
// ownership: RuntimeAssetStore sets/clears EInternalObjectFlags::RootSet on the
// asset's FUObjectItem -- exactly what UObject::AddToRoot()/RemoveFromRoot() do
// (UObjectBaseUtility.h:196-205). Rooting happens INSIDE the same GameThread job
// as the load, so there is no window in which the fresh, unreferenced asset could
// be collected before the runtime owns it.
#include <atomic>
#include <cstdint>

#include "GameThreadDispatcher.h"
#include "UE54TickerCarrier.h"
#include "RuntimeAssetStore.h"
#include "../Public/MiseryGameThread.h"
#include "../Public/MiseryAssets.h"
#include "Containers/UnrealString.h"
#include "HAL/PlatformTLS.h"

using Misery::Internal::CarrierBindings;
using Misery::Internal::GameThreadDispatcher;
using Misery::Internal::IGameThreadCarrier;
using Misery::Internal::RuntimeAssetStore;

static_assert(sizeof(FString) == 16, "FString must be 16 bytes");
static constexpr int OFF_DATA = 0, OFF_NUM = 8, OFF_MAX = 12;
using ProcessEventFn = void(__fastcall*)(void*, void*, void*);
using MallocFn = void* (*)(size_t, uint32_t);
using FreeFn = void(__fastcall*)(void*, void*);

namespace {

constexpr uint64_t kMagic = 0x4950502D43523141ULL;  // "IPP-CR1A"
constexpr uint32_t kProto = 1;
constexpr int kPathMax = 128;

#pragma pack(push, 1)
struct Cr01aIo {
    uint64_t magic; uint32_t proto; uint32_t max_jobs_per_tick;
    uint64_t add_ticker, get_core_ticker, fmemory_malloc;
    uint8_t sig_add[16], sig_get[16], sig_malloc[16];
    uint64_t gmalloc_ptr_va; uint32_t free_slot_disp; uint32_t pad0;
    uint64_t cdo, process_event, fn_make, fn_load;
    uint64_t objects_ptr;              // GUObjectArray chunk pointer array
    uint32_t internal_index_offset;    // UObjectBase::InternalIndex (+0xC)
    uint32_t pad1;
    uint16_t target_path[kPathMax];
    // outputs
    uint32_t activated, initialized, state, wait_stopped_ok;
    uint32_t load_ran, load_tid, fstring_ok, freed;
    uint64_t asset_ptr, item_ptr, handle;
    uint32_t rooted_after_acquire, owned_after_acquire;
    uint32_t release_ran, rooted_after_release, owned_after_release, release_ok;
    uint32_t release_unknown_returned, duplicate_handle_same, owned_after_duplicate;
    uint32_t released_at_shutdown;
    uint32_t reserved[3];
};
#pragma pack(pop)
static_assert(sizeof(Cr01aIo) == 516, "Cr01aIo layout must match the controller");

Cr01aIo* g_io = nullptr;
GameThreadDispatcher* g_disp = nullptr;
IGameThreadCarrier* g_carrier = nullptr;
RuntimeAssetStore* g_store = nullptr;
MallocFn g_malloc = nullptr;
std::atomic<uint32_t> g_phase{0};

void GameFree(void* p) {
    if (!p || !g_io) return;
    void* fm = *reinterpret_cast<void**>(static_cast<uintptr_t>(g_io->gmalloc_ptr_va));
    if (!fm) return;
    void** vt = *reinterpret_cast<void***>(fm);
    reinterpret_cast<FreeFn>(vt[g_io->free_slot_disp / 8])(fm, p);
}

int PathLen(const uint16_t* s) { int n = 0; while (s[n]) ++n; return n; }

// FUObjectItem* for a UObject*, using the chunked GUObjectArray layout.
void* ItemForObject(const void* obj) {
    if (!obj || !g_io->objects_ptr) return nullptr;
    const int32_t idx = *reinterpret_cast<const int32_t*>(
        reinterpret_cast<const unsigned char*>(obj) + g_io->internal_index_offset);
    if (idx < 0) return nullptr;
    void* chunk = *reinterpret_cast<void**>(
        static_cast<uintptr_t>(g_io->objects_ptr) + (static_cast<uint32_t>(idx) >> 16) * 8);
    if (!chunk) return nullptr;
    return reinterpret_cast<unsigned char*>(chunk) + (idx & 0xFFFF) * 0x18;
}

// GameThread job: proven P-04 load, then IMMEDIATE runtime ownership.
void JobLoadAndAcquire(void*) {
    Cr01aIo* io = g_io;
    io->load_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    alignas(8) unsigned char p1[48] = {};
    alignas(8) unsigned char p2[48] = {};
    const int len = PathLen(io->target_path);
    TCHAR* buf = static_cast<TCHAR*>(g_malloc(static_cast<size_t>(len + 1) * sizeof(TCHAR), 0u));
    if (!buf) { io->load_ran = 2; return; }
    for (int i = 0; i < len; ++i) buf[i] = static_cast<TCHAR>(io->target_path[i]);
    buf[len] = TEXT('\0');
    *reinterpret_cast<void**>(p1 + OFF_DATA) = buf;
    *reinterpret_cast<int32*>(p1 + OFF_NUM) = len + 1;
    *reinterpret_cast<int32*>(p1 + OFF_MAX) = len + 1;
    const FString& s = *reinterpret_cast<const FString*>(p1);
    io->fstring_ok = (s.Len() == len && !s.IsEmpty()) ? 1u : 0u;

    auto pe = reinterpret_cast<ProcessEventFn>(static_cast<uintptr_t>(io->process_event));
    void* cdo = reinterpret_cast<void*>(static_cast<uintptr_t>(io->cdo));
    pe(cdo, reinterpret_cast<void*>(static_cast<uintptr_t>(io->fn_make)), p1);
    for (int i = 0; i < 32; ++i) p2[8 + i] = p1[16 + i];
    pe(cdo, reinterpret_cast<void*>(static_cast<uintptr_t>(io->fn_load)), p2);
    void* asset = *reinterpret_cast<void**>(p2 + 40);
    io->asset_ptr = reinterpret_cast<uint64_t>(asset);

    GameFree(buf);
    *reinterpret_cast<void**>(p1 + OFF_DATA) = nullptr;
    *reinterpret_cast<int32*>(p1 + OFF_NUM) = 0;
    *reinterpret_cast<int32*>(p1 + OFF_MAX) = 0;
    io->freed = 1;

    // ---- runtime takes ownership, in the SAME job (no GC window) ----
    void* item = ItemForObject(asset);
    io->item_ptr = reinterpret_cast<uint64_t>(item);
    if (asset && item) {
        io->handle = g_store->Acquire(asset, item);
        io->rooted_after_acquire = g_store->IsRooted(asset) ? 1u : 0u;
        io->owned_after_acquire = g_store->OwnedCount();
        // duplicate-acquire semantics: same handle, count unchanged
        const uint64_t h2 = g_store->Acquire(asset, item);
        io->duplicate_handle_same = (h2 == io->handle) ? 1u : 0u;
        io->owned_after_duplicate = g_store->OwnedCount();
        g_store->Release(h2);              // drop the duplicate reference again
        // releasing an unknown handle must be a tolerated no-op
        io->release_unknown_returned = g_store->Release(0xDEADBEEFULL) ? 1u : 0u;
    }
    io->load_ran = 1;
}

void JobRelease(void*) {
    Cr01aIo* io = g_io;
    io->release_ok = g_store->Release(io->handle) ? 1u : 0u;
    io->rooted_after_release =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(io->asset_ptr))) ? 1u : 0u;
    io->owned_after_release = g_store->OwnedCount();
    io->release_ran = 1;
}

}  // namespace

namespace Misery { namespace GameThread {
bool IsAvailable() { return g_disp && g_disp->stats().state.load() == GameThreadDispatcher::kRunning; }
bool Enqueue(JobFn fn, void* ctx) { return g_disp && g_disp->Enqueue(fn, ctx); }
}}
namespace Misery { namespace Assets {
Handle Acquire(const void* a) { return g_store ? g_store->Acquire(a, ItemForObject(a)) : 0; }
bool Release(Handle h) { return g_store && g_store->Release(h); }
uint32_t OwnedCount() { return g_store ? g_store->OwnedCount() : 0; }
}}

extern "C" __declspec(dllexport) unsigned long Init(void* param) {
    Cr01aIo* io = static_cast<Cr01aIo*>(param);
    if (!io || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
    if (!io->cdo || !io->process_event || !io->fn_make || !io->fn_load ||
        !io->gmalloc_ptr_va || !io->objects_ptr) return 0xFFFFFFFDu;
    g_io = io;
    g_malloc = reinterpret_cast<MallocFn>(static_cast<uintptr_t>(io->fmemory_malloc));
    g_store = new RuntimeAssetStore();
    CarrierBindings b;
    b.add_ticker = io->add_ticker; b.get_core_ticker = io->get_core_ticker;
    b.fmemory_malloc = io->fmemory_malloc;
    for (int i = 0; i < 16; ++i) { b.sig_add[i]=io->sig_add[i]; b.sig_get[i]=io->sig_get[i]; b.sig_malloc[i]=io->sig_malloc[i]; }
    g_carrier = Misery::Internal::CreateUE54TickerCarrier(b);
    g_disp = new GameThreadDispatcher();
    GameThreadDispatcher::Config cfg; cfg.max_jobs_per_tick = 8;
    const bool ok = g_disp->Initialize(g_carrier, cfg);
    io->activated = ok ? 1u : 0u; io->initialized = ok ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    return ok ? 0u : 0xFFFFFFFCu;
}

extern "C" __declspec(dllexport) unsigned long RunLoadAndAcquire(void* p) {
    Cr01aIo* io = static_cast<Cr01aIo*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    return Misery::GameThread::Enqueue(&JobLoadAndAcquire, nullptr) ? 0u : 1u;
}
extern "C" __declspec(dllexport) unsigned long RunRelease(void* p) {
    Cr01aIo* io = static_cast<Cr01aIo*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    return Misery::GameThread::Enqueue(&JobRelease, nullptr) ? 0u : 1u;
}

// Shutdown contract: release EVERY runtime-owned root BEFORE the dispatcher goes
// away and before this module can be unloaded, so no root flag we set outlives us.
extern "C" __declspec(dllexport) unsigned long Shutdown(void* p) {
    Cr01aIo* io = static_cast<Cr01aIo*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    io->released_at_shutdown = g_store->ReleaseAll();
    g_disp->Shutdown(5000);
    io->wait_stopped_ok = g_disp->wait_stopped_ok() ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    delete g_disp; g_disp = nullptr;
    Misery::Internal::DestroyCarrier(g_carrier); g_carrier = nullptr;
    delete g_store; g_store = nullptr;
    return 0u;
}
