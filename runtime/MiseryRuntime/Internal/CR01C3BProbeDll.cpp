// CR-01C3B: Detached Aggregate Runtime Item Table.
//
// Proves the whole Runtime-owned half of architecture B without a single write
// into any vanilla object:
//
//   SpawnObject(UDataTable, /Engine/Transient)     [reflected, engine-native]
//     -> root through the CR-01A engine root path  [SAME GameThread job]
//     -> verify class / outer / vtable / FUObjectItem round-trip
//     -> RowStruct = the live S_ItemDetails UScriptStruct*
//     -> materialize one probe row (CR-01C2R Route C) and AddRow into OUR table
//     -> RemoveRow
//     -> release the root
//
// FAIL CLOSED at every step. The object is rooted BEFORE any reference is
// stored into it, so a write landing mid-incremental-pass can only ever point
// at an object that already has strong vanilla references.
#include <atomic>
#include <cstdint>
#include "GameThreadDispatcher.h"
#include "UE54TickerCarrier.h"
#include "RuntimeAssetStore.h"
#include "../Public/MiseryGameThread.h"
#include "Containers/UnrealString.h"
#include "HAL/PlatformTLS.h"

using Misery::Internal::CarrierBindings;
using Misery::Internal::GameThreadDispatcher;
using Misery::Internal::IGameThreadCarrier;
using Misery::Internal::RuntimeAssetStore;
using Misery::Internal::RootFlagsFn;

static_assert(sizeof(FString) == 16, "FString must be 16 bytes");
static constexpr int OFF_DATA = 0, OFF_NUM = 8, OFF_MAX = 12;

// UObjectBase, ERI-verified: ObjectFlags @0x08, InternalIndex @0x0C,
// ClassPrivate @0x10, OuterPrivate @0x20.
static constexpr int OFF_INTERNAL_INDEX = 0x0C;
static constexpr int OFF_CLASS_PRIVATE = 0x10;
static constexpr int OFF_OUTER_PRIVATE = 0x20;
// FChunkedFixedUObjectArray addressing (RF-05): shift 16 / mask 0xFFFF / stride 24.
static constexpr int SIZEOF_FUOBJECTITEM = 0x18;
// UDataTable::RowStruct, reflected offset.
static constexpr int OFF_ROWSTRUCT = 40;

using ProcessEventFn = void(__fastcall*)(void*, void*, void*);
using MallocFn = void* (*)(size_t, uint32_t);
using FreeFn = void(__fastcall*)(void*);
using StructLifecycleFn = void(__fastcall*)(void* scriptStruct, void* dest, int32_t arrayDim);
using AddRowFn = void(__fastcall*)(void* table, uint64_t rowName, const void* rowData);
using RemoveRowFn = void(__fastcall*)(void* table, uint64_t rowName);

namespace {

constexpr uint64_t kMagic = 0x4950502D43334200ULL;  // "IPP-C3B\0"
constexpr uint32_t kProto = 1;
constexpr int kNameMax = 96;

#pragma pack(push, 1)
struct C3BIo {
    uint64_t magic; uint32_t proto; uint32_t struct_size;
    // carrier
    uint64_t add_ticker, get_core_ticker, fmemory_malloc, fmemory_free;
    uint8_t sig_add[16], sig_get[16], sig_malloc[16];
    // reflection entry points
    uint64_t process_event, cdo_stringlib, fn_conv_str_to_name;
    uint64_t cdo_gameplaystatics, fn_spawn_object;
    // objects
    uint64_t datatable_class, transient_package, row_struct;
    uint64_t item_list, master_item_list, expected_plain_vtable;
    // engine functions
    uint64_t add_row, remove_row, initialize_struct, destroy_struct;
    uint64_t set_root_flags, clear_root_flags;
    uint64_t guobjectarray_objects_ptr;
    // verified field offsets for the probe definition
    uint32_t off_weight, off_width, off_height, off_maxstack, off_allowstacking, pad0;
    double val_weight;
    int32_t val_width, val_height, val_maxstack; uint8_t val_allowstacking; uint8_t pad1[3];
    uint16_t row_name[kNameMax];
    // outputs
    uint32_t activated, initialized, state, wait_stopped_ok;
    uint32_t create_ran, populate_ran, remove_ran, release_ran;
    uint32_t gt_tid, fstring_ok, err, err_step;
    uint64_t table_ptr, table_item_ptr, table_class, table_outer, table_vtable;
    uint64_t table_rowstruct_after, row_fname, temp_ptr, store_handle;
    uint32_t internal_index, rooted_after_acquire, rooted_after_release, temp_freed;
    uint32_t table_addrow_matches, table_removerow_matches, owned_count, item_flags;
    uint64_t reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(C3BIo) == 648, "C3BIo layout must match the controller");

C3BIo* g_io = nullptr;
GameThreadDispatcher* g_disp = nullptr;
IGameThreadCarrier* g_carrier = nullptr;
RuntimeAssetStore* g_store = nullptr;
MallocFn g_malloc = nullptr;
FreeFn g_free = nullptr;

inline uint64_t RD64(uint64_t p) { return *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(p)); }
inline int32_t RD32(uint64_t p) { return *reinterpret_cast<int32_t*>(static_cast<uintptr_t>(p)); }

int NameLen(const uint16_t* s) { int n = 0; while (s[n]) ++n; return n; }

uint64_t InternName() {
    C3BIo* io = g_io;
    alignas(8) unsigned char p[24] = {};
    const int len = NameLen(io->row_name);
    TCHAR* buf = static_cast<TCHAR*>(g_malloc(static_cast<size_t>(len + 1) * sizeof(TCHAR), 0u));
    if (!buf) return 0;
    for (int i = 0; i < len; ++i) buf[i] = static_cast<TCHAR>(io->row_name[i]);
    buf[len] = TEXT('\0');
    *reinterpret_cast<void**>(p + OFF_DATA) = buf;
    *reinterpret_cast<int32*>(p + OFF_NUM) = len + 1;
    *reinterpret_cast<int32*>(p + OFF_MAX) = len + 1;
    const FString& s = *reinterpret_cast<const FString*>(p);
    io->fstring_ok = (s.Len() == len && !s.IsEmpty()) ? 1u : 0u;
    reinterpret_cast<ProcessEventFn>(static_cast<uintptr_t>(io->process_event))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->cdo_stringlib)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->fn_conv_str_to_name)), p);
    const uint64_t nm = *reinterpret_cast<uint64_t*>(p + 16);
    g_free(buf);
    return nm;
}

// FUObjectItem* for a live object, from its own InternalIndex. Returns 0 if the
// round trip (item->Object == obj) does not hold.
uint64_t ItemForObject(uint64_t obj) {
    C3BIo* io = g_io;
    const int32_t idx = RD32(obj + OFF_INTERNAL_INDEX);
    if (idx < 0) return 0;
    const uint64_t chunk = RD64(io->guobjectarray_objects_ptr +
                                static_cast<uint64_t>(idx >> 16) * 8);
    if (!chunk) return 0;
    const uint64_t item = chunk + static_cast<uint64_t>(idx & 0xFFFF) * SIZEOF_FUOBJECTITEM;
    if (RD64(item) != obj) return 0;
    io->internal_index = static_cast<uint32_t>(idx);
    return item;
}

#define FAILC(step, code) do { io->err_step = (step); io->err = (code); return false; } while (0)

bool CreateAndRoot() {
    C3BIo* io = g_io;
    // 1. reflected, engine-native construction
    alignas(8) unsigned char parms[24] = {};
    *reinterpret_cast<uint64_t*>(parms + 0) = io->datatable_class;
    *reinterpret_cast<uint64_t*>(parms + 8) = io->transient_package;
    *reinterpret_cast<uint64_t*>(parms + 16) = 0;
    reinterpret_cast<ProcessEventFn>(static_cast<uintptr_t>(io->process_event))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->cdo_gameplaystatics)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->fn_spawn_object)), parms);
    const uint64_t obj = *reinterpret_cast<uint64_t*>(parms + 16);
    if (!obj) FAILC(1, 1);
    io->table_ptr = obj;

    // 2. identity, BEFORE anything is written into it
    io->table_class = RD64(obj + OFF_CLASS_PRIVATE);
    io->table_outer = RD64(obj + OFF_OUTER_PRIVATE);
    io->table_vtable = RD64(obj);
    if (io->table_class != io->datatable_class) FAILC(2, 2);
    if (io->table_outer != io->transient_package) FAILC(2, 3);
    if (io->table_vtable != io->expected_plain_vtable) FAILC(2, 4);

    // 3. its own FUObjectItem, by round trip
    const uint64_t item = ItemForObject(obj);
    if (!item) FAILC(3, 5);
    io->table_item_ptr = item;

    // 4. root it through the engine's own path, in THIS job
    io->store_handle = g_store->Acquire(reinterpret_cast<void*>(static_cast<uintptr_t>(obj)),
                                        reinterpret_cast<void*>(static_cast<uintptr_t>(item)));
    if (!io->store_handle) FAILC(4, 6);
    io->item_flags = static_cast<uint32_t>(RD32(item + 8));
    io->rooted_after_acquire =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(obj))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    if (!io->rooted_after_acquire) FAILC(4, 7);

    // 5. only now store a reference INTO our table: TObjectPtr is a plain
    //    UObject* here (UE_WITH_OBJECT_HANDLE_LATE_RESOLVE == WITH_EDITORONLY_DATA == 0)
    *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(obj + OFF_ROWSTRUCT)) = io->row_struct;
    io->table_rowstruct_after = RD64(obj + OFF_ROWSTRUCT);
    if (io->table_rowstruct_after != io->row_struct) FAILC(5, 8);

    // 6. our table must dispatch the REAL UDataTable row API, not an override
    const uint64_t vt = io->table_vtable;
    io->table_addrow_matches = (RD64(vt + 95 * 8) == io->add_row) ? 1u : 0u;
    io->table_removerow_matches = (RD64(vt + 94 * 8) == io->remove_row) ? 1u : 0u;
    if (!io->table_addrow_matches || !io->table_removerow_matches) FAILC(6, 9);
    return true;
}

void JobCreate(void*) {
    C3BIo* io = g_io;
    io->gt_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    io->create_ran = CreateAndRoot() ? 1u : 2u;
}

void JobPopulate(void*) {
    C3BIo* io = g_io;
    if (!io->table_ptr || io->create_ran != 1) { io->err = 20; io->populate_ran = 2; return; }
    if (!io->row_fname) io->row_fname = InternName();
    if (!io->row_fname) { io->err = 21; io->populate_ran = 2; return; }
    if (io->struct_size < 64 || io->struct_size > (1u << 20)) { io->err = 22; io->populate_ran = 2; return; }

    void* rs = reinterpret_cast<void*>(static_cast<uintptr_t>(io->row_struct));
    auto init = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->initialize_struct));
    auto destroy = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->destroy_struct));

    uint8_t* temp = static_cast<uint8_t*>(g_malloc(io->struct_size, 0u));
    if (!temp) { io->err = 23; io->populate_ran = 2; return; }
    io->temp_ptr = reinterpret_cast<uint64_t>(temp);
    init(rs, temp, 1);
    *reinterpret_cast<double*>(temp + io->off_weight) = io->val_weight;
    *reinterpret_cast<int32_t*>(temp + io->off_width) = io->val_width;
    *reinterpret_cast<int32_t*>(temp + io->off_height) = io->val_height;
    *reinterpret_cast<int32_t*>(temp + io->off_maxstack) = io->val_maxstack;
    *reinterpret_cast<uint8_t*>(temp + io->off_allowstacking) = io->val_allowstacking;

    reinterpret_cast<AddRowFn>(static_cast<uintptr_t>(io->add_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr)), io->row_fname, temp);

    destroy(rs, temp, 1);
    g_free(temp);
    io->temp_freed = 1;
    io->populate_ran = 1;
}

void JobRemove(void*) {
    C3BIo* io = g_io;
    if (!io->table_ptr || !io->row_fname) { io->err = 30; io->remove_ran = 2; return; }
    reinterpret_cast<RemoveRowFn>(static_cast<uintptr_t>(io->remove_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr)), io->row_fname);
    io->remove_ran = 1;
}

void JobRelease(void*) {
    C3BIo* io = g_io;
    if (!io->store_handle) { io->err = 40; io->release_ran = 2; return; }
    const bool ok = g_store->Release(io->store_handle);
    io->rooted_after_release =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    io->item_flags = static_cast<uint32_t>(RD32(io->table_item_ptr + 8));
    io->release_ran = ok ? 1u : 2u;
}

}  // namespace

namespace Misery { namespace GameThread {
bool IsAvailable() { return g_disp && g_disp->stats().state.load() == GameThreadDispatcher::kRunning; }
bool Enqueue(JobFn fn, void* ctx) { return g_disp && g_disp->Enqueue(fn, ctx); }
}}

extern "C" __declspec(dllexport) unsigned long Init(void* param) {
    C3BIo* io = static_cast<C3BIo*>(param);
    if (!io || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
    if (!io->process_event || !io->cdo_stringlib || !io->fn_conv_str_to_name ||
        !io->cdo_gameplaystatics || !io->fn_spawn_object || !io->datatable_class ||
        !io->transient_package || !io->row_struct || !io->item_list || !io->master_item_list ||
        !io->expected_plain_vtable || !io->add_row || !io->remove_row ||
        !io->initialize_struct || !io->destroy_struct || !io->set_root_flags ||
        !io->clear_root_flags || !io->guobjectarray_objects_ptr ||
        !io->fmemory_malloc || !io->fmemory_free) return 0xFFFFFFFDu;
    g_io = io;
    g_malloc = reinterpret_cast<MallocFn>(static_cast<uintptr_t>(io->fmemory_malloc));
    g_free = reinterpret_cast<FreeFn>(static_cast<uintptr_t>(io->fmemory_free));
    g_store = new RuntimeAssetStore();
    g_store->SetRootPath(reinterpret_cast<RootFlagsFn>(static_cast<uintptr_t>(io->set_root_flags)),
                         reinterpret_cast<RootFlagsFn>(static_cast<uintptr_t>(io->clear_root_flags)));
    if (!g_store->HasRootPath()) return 0xFFFFFFFBu;
    CarrierBindings b;
    b.add_ticker = io->add_ticker; b.get_core_ticker = io->get_core_ticker;
    b.fmemory_malloc = io->fmemory_malloc;
    for (int i = 0; i < 16; ++i) {
        b.sig_add[i] = io->sig_add[i]; b.sig_get[i] = io->sig_get[i]; b.sig_malloc[i] = io->sig_malloc[i];
    }
    g_carrier = Misery::Internal::CreateUE54TickerCarrier(b);
    g_disp = new GameThreadDispatcher();
    GameThreadDispatcher::Config cfg; cfg.max_jobs_per_tick = 8;
    const bool ok = g_disp->Initialize(g_carrier, cfg);
    io->activated = ok ? 1u : 0u; io->initialized = ok ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    return ok ? 0u : 0xFFFFFFFCu;
}

#define EXPORT_JOB(NAME, FN)                                                        \
    extern "C" __declspec(dllexport) unsigned long NAME(void* p) {                  \
        C3BIo* io = static_cast<C3BIo*>(p);                                         \
        if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;                       \
        return Misery::GameThread::Enqueue(&FN, nullptr) ? 0u : 1u;                 \
    }
EXPORT_JOB(RunCreate, JobCreate)
EXPORT_JOB(RunPopulate, JobPopulate)
EXPORT_JOB(RunRemove, JobRemove)
EXPORT_JOB(RunRelease, JobRelease)

extern "C" __declspec(dllexport) unsigned long Shutdown(void* p) {
    C3BIo* io = static_cast<C3BIo*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    // contract: no runtime-owned root may outlive this module
    const uint32_t released = g_store->ReleaseAll();
    io->owned_count = g_store->OwnedCount();
    g_disp->Shutdown(5000);
    io->wait_stopped_ok = g_disp->wait_stopped_ok() ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    delete g_disp; g_disp = nullptr;
    Misery::Internal::DestroyCarrier(g_carrier); g_carrier = nullptr;
    delete g_store; g_store = nullptr;
    return released;
}
