// CR-01C2R Route C: Runtime materialization of a real S_ItemDetails row.
//
//   game-allocator temp buffer (size = real RowStruct->PropertiesSize)
//     -> UScriptStruct::InitializeStruct(temp)      [struct vtable slot 96]
//     -> populate ONLY verified trivially-assignable value types by reflected offset
//     -> UDataTable::AddRow(ItemList, runtimeName, temp)   [engine deep-copies]
//     -> UScriptStruct::DestroyStruct(temp)         [struct vtable slot 97]
//     -> FMemory::Free(temp)
//   The target row must remain valid after the temp is destroyed independently.
//
// Every address is resolved and byte-verified by the controller; the probe refuses
// to run if any is missing. Only value types are stored directly: FString, FText,
// TArray, nested structs and object/soft references are left in the correct state
// InitializeStruct produced, never memcpy'd or pointer-poked.
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
using FreeFn = void(__fastcall*)(void*);
using StructLifecycleFn = void(__fastcall*)(void* scriptStruct, void* dest, int32_t arrayDim);
using AddRowFn = void(__fastcall*)(void* table, uint64_t rowName, const void* rowData);
using RemoveRowFn = void(__fastcall*)(void* table, uint64_t rowName);

namespace {

constexpr uint64_t kMagic = 0x4950502D43325200ULL;  // "IPP-C2R\0"
constexpr uint32_t kProto = 1;
constexpr int kNameMax = 96;

#pragma pack(push, 1)
struct C2RIo {
    uint64_t magic; uint32_t proto; uint32_t struct_size;
    uint64_t add_ticker, get_core_ticker, fmemory_malloc, fmemory_free;
    uint8_t sig_add[16], sig_get[16], sig_malloc[16];
    uint64_t process_event, cdo_stringlib, fn_conv_str_to_name;
    uint64_t item_list, add_row, remove_row;
    uint64_t row_struct, initialize_struct, destroy_struct;
    // verified field offsets (controller refuses to arm unless each matched)
    uint32_t off_weight, off_width, off_height, off_maxstack, off_fueltime, pad0;
    double val_weight, val_fueltime;
    int32_t val_width, val_height, val_maxstack, pad1;
    uint16_t row_name[kNameMax];
    // outputs
    uint32_t activated, initialized, state, wait_stopped_ok;
    uint32_t materialize_ran, remove_ran, gt_tid, fstring_ok;
    uint64_t row_fname, temp_ptr;
    uint32_t temp_freed, err, pad2, pad3;
    uint64_t reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(C2RIo) == 496, "C2RIo layout must match the controller");

C2RIo* g_io = nullptr;
GameThreadDispatcher* g_disp = nullptr;
IGameThreadCarrier* g_carrier = nullptr;
MallocFn g_malloc = nullptr;
FreeFn g_free = nullptr;

int NameLen(const uint16_t* s) { int n = 0; while (s[n]) ++n; return n; }

uint64_t InternName() {
    C2RIo* io = g_io;
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
    *reinterpret_cast<void**>(p + OFF_DATA) = nullptr;
    *reinterpret_cast<int32*>(p + OFF_NUM) = 0;
    *reinterpret_cast<int32*>(p + OFF_MAX) = 0;
    return nm;
}

void JobMaterialize(void*) {
    C2RIo* io = g_io;
    io->gt_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    if (!io->row_fname) io->row_fname = InternName();
    if (!io->row_fname) { io->err = 1; io->materialize_ran = 2; return; }
    if (io->struct_size < 64 || io->struct_size > (1u << 20)) { io->err = 2; io->materialize_ran = 2; return; }

    void* rs = reinterpret_cast<void*>(static_cast<uintptr_t>(io->row_struct));
    auto init = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->initialize_struct));
    auto destroy = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->destroy_struct));

    // 1. game-allocator temp buffer, sized from the REAL RowStruct
    uint8_t* temp = static_cast<uint8_t*>(g_malloc(io->struct_size, 0u));
    if (!temp) { io->err = 3; io->materialize_ran = 2; return; }
    io->temp_ptr = reinterpret_cast<uint64_t>(temp);

    // 2. proper UE construction of the real struct
    init(rs, temp, 1);

    // 3. populate ONLY verified trivially-assignable value types
    *reinterpret_cast<double*>(temp + io->off_weight)   = io->val_weight;
    *reinterpret_cast<int32_t*>(temp + io->off_width)   = io->val_width;
    *reinterpret_cast<int32_t*>(temp + io->off_height)  = io->val_height;
    *reinterpret_cast<int32_t*>(temp + io->off_maxstack) = io->val_maxstack;
    *reinterpret_cast<double*>(temp + io->off_fueltime) = io->val_fueltime;

    // 4. engine deep-copies our temp into a row it owns
    reinterpret_cast<AddRowFn>(static_cast<uintptr_t>(io->add_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->item_list)), io->row_fname, temp);

    // 5. destroy and free the temp INDEPENDENTLY -- the target row must survive
    destroy(rs, temp, 1);
    g_free(temp);
    io->temp_freed = 1;
    io->materialize_ran = 1;
}

void JobRemove(void*) {
    C2RIo* io = g_io;
    if (!io->row_fname) { io->err = 4; io->remove_ran = 2; return; }
    reinterpret_cast<RemoveRowFn>(static_cast<uintptr_t>(io->remove_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->item_list)), io->row_fname);
    io->remove_ran = 1;
}

}  // namespace

namespace Misery { namespace GameThread {
bool IsAvailable() { return g_disp && g_disp->stats().state.load() == GameThreadDispatcher::kRunning; }
bool Enqueue(JobFn fn, void* ctx) { return g_disp && g_disp->Enqueue(fn, ctx); }
}}

extern "C" __declspec(dllexport) unsigned long Init(void* param) {
    C2RIo* io = static_cast<C2RIo*>(param);
    if (!io || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
    if (!io->process_event || !io->cdo_stringlib || !io->fn_conv_str_to_name ||
        !io->item_list || !io->add_row || !io->remove_row || !io->row_struct ||
        !io->initialize_struct || !io->destroy_struct ||
        !io->fmemory_malloc || !io->fmemory_free) return 0xFFFFFFFDu;
    g_io = io;
    g_malloc = reinterpret_cast<MallocFn>(static_cast<uintptr_t>(io->fmemory_malloc));
    g_free = reinterpret_cast<FreeFn>(static_cast<uintptr_t>(io->fmemory_free));
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

extern "C" __declspec(dllexport) unsigned long RunMaterialize(void* p) {
    C2RIo* io = static_cast<C2RIo*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    return Misery::GameThread::Enqueue(&JobMaterialize, nullptr) ? 0u : 1u;
}
extern "C" __declspec(dllexport) unsigned long RunRemove(void* p) {
    C2RIo* io = static_cast<C2RIo*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    return Misery::GameThread::Enqueue(&JobRemove, nullptr) ? 0u : 1u;
}
extern "C" __declspec(dllexport) unsigned long Shutdown(void* p) {
    C2RIo* io = static_cast<C2RIo*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    g_disp->Shutdown(5000);
    io->wait_stopped_ok = g_disp->wait_stopped_ok() ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    delete g_disp; g_disp = nullptr;
    Misery::Internal::DestroyCarrier(g_carrier); g_carrier = nullptr;
    return 0u;
}
