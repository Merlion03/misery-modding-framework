// CR-01C3C: Publish the Runtime aggregate table into MasterItemList.
//
// The ONE authorised vanilla write of this gate: append the Runtime-owned table
// as a second parent of MasterItemList, let the engine publish it through its
// own delegate path, then roll back exactly.
//
//   [C3B, unchanged] spawn -> root -> RowStruct -> materialize -> AddRow
//   attach : verify -> element[1] = table -> Num 1->2 -> data-neutral trigger
//   detach : Num 2->1 -> data-neutral trigger
//   zero   : element[1] = 0        (restore the spare-capacity bytes)
//   release: drop the root
//
// The trigger is UDataTable::RemoveRow(ItemList, <a name that is not in it>).
// RemoveRowInternal leaves RowData null on a miss, so nothing is destroyed or
// freed (DataTable.cpp:433-451); its only effect is the FScopedDataTableChange
// destructor's broadcast, which is what drives OnParentTablesUpdated ->
// UpdateCachedRowMap -> subscribe. No growth of ParentTables is ever performed:
// the attach refuses unless Max - Num >= 1 already.
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
static constexpr int OFF_INTERNAL_INDEX = 0x0C;
static constexpr int OFF_CLASS_PRIVATE = 0x10;
static constexpr int OFF_OUTER_PRIVATE = 0x20;
static constexpr int SIZEOF_FUOBJECTITEM = 0x18;

using ProcessEventFn = void(__fastcall*)(void*, void*, void*);
using MallocFn = void* (*)(size_t, uint32_t);
using FreeFn = void(__fastcall*)(void*);
using StructLifecycleFn = void(__fastcall*)(void* scriptStruct, void* dest, int32_t arrayDim);
using AddRowFn = void(__fastcall*)(void* table, uint64_t rowName, const void* rowData);
using RemoveRowFn = void(__fastcall*)(void* table, uint64_t rowName);

namespace {

constexpr uint64_t kMagic = 0x4950502D43334300ULL;  // "IPP-C3C\0"
constexpr uint32_t kProto = 1;
constexpr int kNameMax = 96;

#pragma pack(push, 1)
struct C3CIo {
    uint64_t magic; uint32_t proto; uint32_t struct_size;
    uint64_t add_ticker, get_core_ticker, fmemory_malloc, fmemory_free;
    uint8_t sig_add[16], sig_get[16], sig_malloc[16];
    uint64_t process_event, cdo_stringlib, fn_conv_str_to_name;
    uint64_t cdo_gameplaystatics, fn_spawn_object;
    uint64_t datatable_class, transient_package, row_struct;
    uint64_t item_list, master_item_list, expected_plain_vtable;
    uint64_t expected_composite_vtable, master_class;
    uint64_t add_row, remove_row, initialize_struct, destroy_struct;
    uint64_t set_root_flags, clear_root_flags;
    uint64_t guobjectarray_objects_ptr;
    uint32_t off_parent_tables, off_rowstruct, off_delegate, pad0;
    uint32_t off_weight, off_width, off_height, off_maxstack, off_allowstacking, pad1;
    double val_weight;
    int32_t val_width, val_height, val_maxstack; uint8_t val_allowstacking; uint8_t pad2[3];
    uint16_t row_name[kNameMax];
    uint16_t trigger_name[kNameMax];
    // outputs
    uint32_t activated, initialized, state, wait_stopped_ok;
    uint32_t create_ran, populate_ran, attach_ran, detach_ran;
    uint32_t zero_ran, release_ran, gt_tid, fstring_ok;
    uint32_t err, err_step, internal_index, temp_freed;
    uint32_t rooted_after_acquire, rooted_after_release, owned_count, item_flags;
    uint32_t table_addrow_matches, table_removerow_matches, pad3, pad4;
    uint64_t table_ptr, table_item_ptr, table_class, table_outer, table_vtable;
    uint64_t table_rowstruct_after, row_fname, trigger_fname, temp_ptr, store_handle;
    uint64_t parent_data, parent_elem0, parent_elem1_before, parent_elem1_after;
    uint32_t parent_num_before, parent_max, parent_num_after_attach, parent_num_after_detach;
    uint64_t reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(C3CIo) == 944, "C3CIo layout must match the controller");

C3CIo* g_io = nullptr;
GameThreadDispatcher* g_disp = nullptr;
IGameThreadCarrier* g_carrier = nullptr;
RuntimeAssetStore* g_store = nullptr;
MallocFn g_malloc = nullptr;
FreeFn g_free = nullptr;

inline uint64_t RD64(uint64_t p) { return *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(p)); }
inline int32_t RD32(uint64_t p) { return *reinterpret_cast<int32_t*>(static_cast<uintptr_t>(p)); }
inline void WR64(uint64_t p, uint64_t v) { *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(p)) = v; }
inline void WR32(uint64_t p, int32_t v) { *reinterpret_cast<int32_t*>(static_cast<uintptr_t>(p)) = v; }

int NameLen(const uint16_t* s) { int n = 0; while (s[n]) ++n; return n; }

uint64_t InternName(const uint16_t* src) {
    C3CIo* io = g_io;
    alignas(8) unsigned char p[24] = {};
    const int len = NameLen(src);
    TCHAR* buf = static_cast<TCHAR*>(g_malloc(static_cast<size_t>(len + 1) * sizeof(TCHAR), 0u));
    if (!buf) return 0;
    for (int i = 0; i < len; ++i) buf[i] = static_cast<TCHAR>(src[i]);
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

uint64_t ItemForObject(uint64_t obj) {
    C3CIo* io = g_io;
    const int32_t idx = RD32(obj + OFF_INTERNAL_INDEX);
    if (idx < 0) return 0;
    const uint64_t chunk = RD64(io->guobjectarray_objects_ptr + static_cast<uint64_t>(idx >> 16) * 8);
    if (!chunk) return 0;
    const uint64_t item = chunk + static_cast<uint64_t>(idx & 0xFFFF) * SIZEOF_FUOBJECTITEM;
    if (RD64(item) != obj) return 0;
    io->internal_index = static_cast<uint32_t>(idx);
    return item;
}

// The one engine-native, data-neutral way we make the composite re-read its
// parents: a RemoveRow of a name ItemList does not contain.
void FireNeutralTrigger() {
    C3CIo* io = g_io;
    reinterpret_cast<RemoveRowFn>(static_cast<uintptr_t>(io->remove_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->item_list)), io->trigger_fname);
}

#define FAILC(step, code) do { io->err_step = (step); io->err = (code); return false; } while (0)

bool CreateAndRoot() {
    C3CIo* io = g_io;
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
    io->table_class = RD64(obj + OFF_CLASS_PRIVATE);
    io->table_outer = RD64(obj + OFF_OUTER_PRIVATE);
    io->table_vtable = RD64(obj);
    if (io->table_class != io->datatable_class) FAILC(2, 2);
    if (io->table_outer != io->transient_package) FAILC(2, 3);
    if (io->table_vtable != io->expected_plain_vtable) FAILC(2, 4);
    const uint64_t item = ItemForObject(obj);
    if (!item) FAILC(3, 5);
    io->table_item_ptr = item;
    io->store_handle = g_store->Acquire(reinterpret_cast<void*>(static_cast<uintptr_t>(obj)),
                                        reinterpret_cast<void*>(static_cast<uintptr_t>(item)));
    if (!io->store_handle) FAILC(4, 6);
    io->item_flags = static_cast<uint32_t>(RD32(item + 8));
    io->rooted_after_acquire =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(obj))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    if (!io->rooted_after_acquire) FAILC(4, 7);
    WR64(obj + io->off_rowstruct, io->row_struct);
    io->table_rowstruct_after = RD64(obj + io->off_rowstruct);
    if (io->table_rowstruct_after != io->row_struct) FAILC(5, 8);
    const uint64_t vt = io->table_vtable;
    io->table_addrow_matches = (RD64(vt + 95 * 8) == io->add_row) ? 1u : 0u;
    io->table_removerow_matches = (RD64(vt + 94 * 8) == io->remove_row) ? 1u : 0u;
    if (!io->table_addrow_matches || !io->table_removerow_matches) FAILC(6, 9);
    // intern both names up front so no job after this one can fail on naming
    io->row_fname = InternName(io->row_name);
    if (!io->row_fname) FAILC(7, 10);
    io->trigger_fname = InternName(io->trigger_name);
    if (!io->trigger_fname) FAILC(7, 11);
    if (io->trigger_fname == io->row_fname) FAILC(7, 12);
    return true;
}

void JobCreate(void*) {
    C3CIo* io = g_io;
    io->gt_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    io->create_ran = CreateAndRoot() ? 1u : 2u;
}

void JobPopulate(void*) {
    C3CIo* io = g_io;
    if (!io->table_ptr || io->create_ran != 1) { io->err = 20; io->populate_ran = 2; return; }
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

// ---- the one authorised vanilla write -----------------------------------
bool Attach() {
    C3CIo* io = g_io;
    const uint64_t master = io->master_item_list;
    if (RD64(master) != io->expected_composite_vtable) FAILC(10, 30);
    if (RD64(master + OFF_CLASS_PRIVATE) != io->master_class) FAILC(10, 31);
    if (RD64(master + io->off_rowstruct) != io->row_struct) FAILC(10, 32);

    const uint64_t pt = master + io->off_parent_tables;
    const uint64_t data = RD64(pt + OFF_DATA);
    const int32_t num = RD32(pt + OFF_NUM);
    const int32_t maxn = RD32(pt + OFF_MAX);
    io->parent_data = data; io->parent_num_before = static_cast<uint32_t>(num);
    io->parent_max = static_cast<uint32_t>(maxn);
    if (!data) FAILC(11, 33);
    if (num != 1) FAILC(11, 34);
    if (maxn - num < 1) FAILC(11, 35);          // NO growth is authorised
    io->parent_elem0 = RD64(data + 0);
    io->parent_elem1_before = RD64(data + 8);
    if (io->parent_elem0 != io->item_list) FAILC(11, 36);
    if (io->parent_elem1_before != 0) FAILC(11, 37);

    if (!io->table_ptr) FAILC(12, 38);
    if (!g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr)))) FAILC(12, 39);
    if (RD64(io->table_ptr + io->off_rowstruct) != io->row_struct) FAILC(12, 40);
    if (RD64(io->table_ptr) != io->expected_plain_vtable) FAILC(12, 41);

    // element[1] = RuntimeTable, then Num 1 -> 2. The referent is already a
    // registered GC root, so no reachability barrier can matter here.
    WR64(data + 8, io->table_ptr);
    WR32(pt + OFF_NUM, 2);
    io->parent_num_after_attach = static_cast<uint32_t>(RD32(pt + OFF_NUM));
    io->parent_elem1_after = RD64(data + 8);
    if (io->parent_num_after_attach != 2 || io->parent_elem1_after != io->table_ptr) FAILC(13, 42);

    FireNeutralTrigger();
    return true;
}

void JobAttach(void*) { C3CIo* io = g_io; io->attach_ran = Attach() ? 1u : 2u; }

void JobDetach(void*) {
    C3CIo* io = g_io;
    const uint64_t pt = io->master_item_list + io->off_parent_tables;
    const uint64_t data = RD64(pt + OFF_DATA);
    if (!data || data != io->parent_data) { io->err = 50; io->detach_ran = 2; return; }
    if (RD32(pt + OFF_NUM) != 2) { io->err = 51; io->detach_ran = 2; return; }
    WR32(pt + OFF_NUM, 1);
    io->parent_num_after_detach = static_cast<uint32_t>(RD32(pt + OFF_NUM));
    FireNeutralTrigger();
    io->detach_ran = 1;
}

// Restore the spare-capacity bytes so no stale pointer is left beyond Num.
void JobZeroSlot(void*) {
    C3CIo* io = g_io;
    const uint64_t pt = io->master_item_list + io->off_parent_tables;
    const uint64_t data = RD64(pt + OFF_DATA);
    if (!data || data != io->parent_data) { io->err = 60; io->zero_ran = 2; return; }
    if (RD32(pt + OFF_NUM) != 1) { io->err = 61; io->zero_ran = 2; return; }
    WR64(data + 8, 0);
    io->zero_ran = (RD64(data + 8) == 0) ? 1u : 2u;
}

void JobRelease(void*) {
    C3CIo* io = g_io;
    if (!io->store_handle) { io->err = 70; io->release_ran = 2; return; }
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
    C3CIo* io = static_cast<C3CIo*>(param);
    if (!io || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
    if (!io->process_event || !io->cdo_stringlib || !io->fn_conv_str_to_name ||
        !io->cdo_gameplaystatics || !io->fn_spawn_object || !io->datatable_class ||
        !io->transient_package || !io->row_struct || !io->item_list || !io->master_item_list ||
        !io->expected_plain_vtable || !io->expected_composite_vtable || !io->master_class ||
        !io->add_row || !io->remove_row || !io->initialize_struct || !io->destroy_struct ||
        !io->set_root_flags || !io->clear_root_flags || !io->guobjectarray_objects_ptr ||
        !io->fmemory_malloc || !io->fmemory_free || !io->off_parent_tables ||
        !io->off_rowstruct || !io->off_delegate) return 0xFFFFFFFDu;
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
        C3CIo* io = static_cast<C3CIo*>(p);                                         \
        if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;                       \
        return Misery::GameThread::Enqueue(&FN, nullptr) ? 0u : 1u;                 \
    }
EXPORT_JOB(RunCreate, JobCreate)
EXPORT_JOB(RunPopulate, JobPopulate)
EXPORT_JOB(RunAttach, JobAttach)
EXPORT_JOB(RunDetach, JobDetach)
EXPORT_JOB(RunZeroSlot, JobZeroSlot)
EXPORT_JOB(RunRelease, JobRelease)

extern "C" __declspec(dllexport) unsigned long Shutdown(void* p) {
    C3CIo* io = static_cast<C3CIo*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
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
