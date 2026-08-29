// CR-01C1: safe ADDITIVE row registration into the live vanilla ItemList.
//
// Uses the engine's own virtual UDataTable::AddRow / RemoveRow, so ALL row memory
// ownership stays inside the engine (source, DataTable.cpp):
//   AddRow    -> RemoveRowInternal(name) ; FMemory::Malloc(struct size) ;
//                InitializeStruct ; CopyScriptStruct (deep copy) ; RowMap.Add
//   RemoveRow -> RemoveAndCopyValue ; DestroyStruct ; FMemory::Free
// The runtime therefore allocates nothing and frees nothing, so no double-free and
// no dangling row is structurally possible from our side. This is also exactly why
// a mod table row POINTER must never be inserted into another table: both tables
// would then own it. We pass a SOURCE pointer that AddRow deep-copies FROM.
//
// Fixture: clone one existing valid vanilla S_ItemDetails row under an unused name,
// isolating row construction / insertion / lookup / rollback from any custom
// content question. No inventory, spawn, crafting or gameplay use of the row.
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

static_assert(sizeof(FString) == 16, "FString must be 16 bytes");
static constexpr int OFF_DATA = 0, OFF_NUM = 8, OFF_MAX = 12;

using ProcessEventFn = void(__fastcall*)(void*, void*, void*);
using MallocFn = void* (*)(size_t, uint32_t);
using FreeFn = void(__fastcall*)(void*, void*);
// UDataTable virtuals, resolved from the table's own vtable (slots 95 / 94).
using AddRowFn = void(__fastcall*)(void* table, uint64_t rowName, const void* rowData);
using RemoveRowFn = void(__fastcall*)(void* table, uint64_t rowName);

namespace {

constexpr uint64_t kMagic = 0x4950502D43314331ULL;  // "IPP-C1C1"
constexpr uint32_t kProto = 1;
constexpr int kNameMax = 96;

#pragma pack(push, 1)
struct C1Io {
    uint64_t magic; uint32_t proto; uint32_t pad0;
    uint64_t add_ticker, get_core_ticker, fmemory_malloc;
    uint8_t sig_add[16], sig_get[16], sig_malloc[16];
    uint64_t gmalloc_ptr_va; uint32_t free_slot_disp; uint32_t pad1;
    uint64_t process_event, cdo_stringlib, fn_conv_str_to_name;
    uint64_t item_list;
    uint64_t add_row, remove_row;
    uint64_t source_row_ptr;
    uint16_t probe_name[kNameMax];
    uint32_t activated, initialized, state, wait_stopped_ok;
    uint32_t intern_ran, add_ran, remove_ran, gt_tid;
    uint64_t probe_fname;
    uint32_t fstring_ok, add_rc, remove_rc, pad2;
    uint64_t reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(C1Io) == 424, "C1Io layout must match the controller");

C1Io* g_io = nullptr;
GameThreadDispatcher* g_disp = nullptr;
IGameThreadCarrier* g_carrier = nullptr;
MallocFn g_malloc = nullptr;

void GameFree(void* p) {
    if (!p || !g_io) return;
    void* fm = *reinterpret_cast<void**>(static_cast<uintptr_t>(g_io->gmalloc_ptr_va));
    if (!fm) return;
    void** vt = *reinterpret_cast<void***>(fm);
    reinterpret_cast<FreeFn>(vt[g_io->free_slot_disp / 8])(fm, p);
}

int NameLen(const uint16_t* s) { int n = 0; while (s[n]) ++n; return n; }

// Let the ENGINE mint the probe key: reflected KismetStringLibrary::Conv_StringToName
// (ParmsSize 24, FString in @0, FName return @16).
uint64_t InternProbeName() {
    C1Io* io = g_io;
    alignas(8) unsigned char p[24] = {};
    const int len = NameLen(io->probe_name);
    TCHAR* buf = static_cast<TCHAR*>(g_malloc(static_cast<size_t>(len + 1) * sizeof(TCHAR), 0u));
    if (!buf) return 0;
    for (int i = 0; i < len; ++i) buf[i] = static_cast<TCHAR>(io->probe_name[i]);
    buf[len] = TEXT('\0');
    *reinterpret_cast<void**>(p + OFF_DATA) = buf;
    *reinterpret_cast<int32*>(p + OFF_NUM) = len + 1;
    *reinterpret_cast<int32*>(p + OFF_MAX) = len + 1;
    const FString& s = *reinterpret_cast<const FString*>(p);
    io->fstring_ok = (s.Len() == len && !s.IsEmpty()) ? 1u : 0u;
    reinterpret_cast<ProcessEventFn>(static_cast<uintptr_t>(io->process_event))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->cdo_stringlib)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->fn_conv_str_to_name)), p);
    const uint64_t name = *reinterpret_cast<uint64_t*>(p + 16);
    GameFree(buf);
    *reinterpret_cast<void**>(p + OFF_DATA) = nullptr;
    *reinterpret_cast<int32*>(p + OFF_NUM) = 0;
    *reinterpret_cast<int32*>(p + OFF_MAX) = 0;
    return name;
}

void JobAdd(void*) {
    C1Io* io = g_io;
    io->gt_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    if (!io->probe_fname) { io->probe_fname = InternProbeName(); io->intern_ran = 1; }
    if (!io->probe_fname || !io->source_row_ptr) { io->add_rc = 1; io->add_ran = 2; return; }
    reinterpret_cast<AddRowFn>(static_cast<uintptr_t>(io->add_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->item_list)),
        io->probe_fname,
        reinterpret_cast<const void*>(static_cast<uintptr_t>(io->source_row_ptr)));
    io->add_ran = 1;
}

void JobRemove(void*) {
    C1Io* io = g_io;
    if (!io->probe_fname) { io->remove_rc = 1; io->remove_ran = 2; return; }
    reinterpret_cast<RemoveRowFn>(static_cast<uintptr_t>(io->remove_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->item_list)), io->probe_fname);
    io->remove_ran = 1;
}

}  // namespace

namespace Misery { namespace GameThread {
bool IsAvailable() { return g_disp && g_disp->stats().state.load() == GameThreadDispatcher::kRunning; }
bool Enqueue(JobFn fn, void* ctx) { return g_disp && g_disp->Enqueue(fn, ctx); }
}}

extern "C" __declspec(dllexport) unsigned long Init(void* param) {
    C1Io* io = static_cast<C1Io*>(param);
    if (!io || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
    if (!io->process_event || !io->cdo_stringlib || !io->fn_conv_str_to_name ||
        !io->item_list || !io->add_row || !io->remove_row || !io->gmalloc_ptr_va)
        return 0xFFFFFFFDu;
    g_io = io;
    g_malloc = reinterpret_cast<MallocFn>(static_cast<uintptr_t>(io->fmemory_malloc));
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

extern "C" __declspec(dllexport) unsigned long RunAdd(void* p) {
    C1Io* io = static_cast<C1Io*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    return Misery::GameThread::Enqueue(&JobAdd, nullptr) ? 0u : 1u;
}

extern "C" __declspec(dllexport) unsigned long RunRemove(void* p) {
    C1Io* io = static_cast<C1Io*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    return Misery::GameThread::Enqueue(&JobRemove, nullptr) ? 0u : 1u;
}

extern "C" __declspec(dllexport) unsigned long Shutdown(void* p) {
    C1Io* io = static_cast<C1Io*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    g_disp->Shutdown(5000);
    io->wait_stopped_ok = g_disp->wait_stopped_ok() ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    delete g_disp; g_disp = nullptr;
    Misery::Internal::DestroyCarrier(g_carrier); g_carrier = nullptr;
    return 0u;
}
