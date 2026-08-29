// CR-01C4B follow-up: a UI-only, in-place patch of the runtime row that
// CR01C4BProbeDll.cpp is already holding.
//
// WHY A SECOND MODULE AT ALL. The first probe is still loaded and is the sole
// owner of two roots -- the runtime UDataTable and the icon UTexture2D. It
// cannot be unloaded to add a job without dropping both, and a loaded DLL
// cannot be extended. So the patch ships as its own module.
//
// WHAT THIS MODULE DELIBERATELY IS NOT. It owns nothing. There is NO
// RuntimeAssetStore here, no Acquire, no Release, no SetRootFlags, no
// LoadAsset_Blocking, no AddRow, no ParentTables write. It never creates an
// object and never changes any object's lifetime. It writes three UI fields
// into a row the other probe already owns, using a texture pointer that probe
// already rooted. That is the whole of it -- which is precisely why "do not
// introduce a second texture / load / root" is satisfied: this module has no
// mechanism with which to introduce one. Its Shutdown releases nothing, so
// unloading it cannot disturb the held state.
//
// HOW IT KNOWS IT HAS THE RIGHT ROW. Not by trusting the pointer it is handed.
// Before writing, it requires the row's InventoryIcon to already equal the icon
// object -- and that texture exists in exactly one row in the game, ours. It
// additionally requires Width/Height/Weight to match the definition. A wrong
// pointer fails closed instead of corrupting a vanilla row.
//
// WHAT MAKES THE EDIT VISIBLE. UCompositeDataTable keeps its OWN COPY of every
// parent row, so patching the parent alone would change nothing the game reads.
// The already-proven data-neutral publication trigger --
// UDataTable::RemoveRow(ItemList, <a name it does not contain>) -- broadcasts
// OnDataTableChanged, and the composite re-copies from its parents. The
// composite's row buffer is reallocated by that rebuild; that is expected and
// was established in CR-01C3C.
#include <atomic>
#include <cstdint>
#include "GameThreadDispatcher.h"
#include "UE54TickerCarrier.h"
#include "../Public/MiseryGameThread.h"
#include "Containers/UnrealString.h"

using Misery::Internal::CarrierBindings;
using Misery::Internal::GameThreadDispatcher;
using Misery::Internal::IGameThreadCarrier;

static_assert(sizeof(FString) == 16, "FString must be 16 bytes");
static constexpr int OFF_DATA = 0, OFF_NUM = 8, OFF_MAX = 12;
static constexpr int FTEXT_SIZE = 16;
static constexpr int CONV_PARMS = 32, CONV_IN = 0, CONV_RET = 16;
static constexpr int IV_ID = 0, IV_AMOUNT = 8, IV_QUICKBIND = 24,
                     IV_ROTATED = 28, IV_USEAMOUNT = 32, IV_INUSE = 36,
                     IV_DURABILITY = 40, IV_DECAYTIME = 44;
static constexpr int AI_ITEM = 0, AI_STACKSEARCH = 48, AI_SHOWNOTIF = 49,
                     AI_REMAINING = 50, AI_REMAINING_ITEM = 56, AI_NEWSLOT = 104,
                     AI_PARMS = 120;
static constexpr int RI_SLOT = 0, RI_REMOVEWEIGHT = 80, RI_REMOVEAMOUNT = 81,
                     RI_SPECIAL = 82, RI_PARMS = 83;
static constexpr int SG_INVITEM = 0, SG_WORLDCTX = 48, SG_FOUND = 56, SG_DETAILS = 64,
                     SG_PARMS = 2336;
static constexpr int TXT_CAP = 128;

using ProcessEventFn = void(__fastcall*)(void*, void*, void*);
using MallocFn = void* (*)(size_t, uint32_t);
using FreeFn = void(__fastcall*)(void*);
using StructLifecycleFn = void(__fastcall*)(void*, void*, int32_t);
using RemoveRowFn = void(__fastcall*)(void*, uint64_t);

namespace {

constexpr uint64_t kMagic = 0x4950502D43345000ULL;  // "IPP-C4P\0"
constexpr uint32_t kProto = 1;
constexpr int kNameMax = 96;

#pragma pack(push, 1)
struct PatchIo {
    uint64_t magic; uint32_t proto; uint32_t struct_size;
    uint64_t add_ticker, get_core_ticker, fmemory_malloc, fmemory_free;
    uint8_t sig_add[16], sig_get[16], sig_malloc[16];
    uint64_t process_event, cdo_stringlib, fn_conv_str_to_name;
    uint64_t cdo_textlib, fn_str_to_text, fn_text_to_str;
    uint64_t cdo_sgkfunctions, fn_sgk_itemdetails;
    uint64_t player_inventory, fn_additem, fn_removeitem;
    uint64_t item_list, master_item_list, runtime_table, remove_row;
    uint64_t initialize_struct, destroy_struct, row_struct;
    uint64_t runtime_row, icon_object;
    uint32_t off_name, off_shortname, off_description, off_inventory_icon;
    uint32_t off_move_icon, off_override_flag, off_override_sizey, off_override_sizex;
    uint32_t off_weight, off_width, off_height, off_maxstack, off_allowstacking, pad0;
    uint32_t want_sizex, want_sizey, want_width, want_height;
    double want_weight;
    int32_t inv_amount, inv_quickbind, inv_useamount, inv_decaytime, inv_rotated, inv_inuse;
    float inv_durability; uint32_t pad1;
    uint16_t row_name[kNameMax];
    uint16_t trigger_name[kNameMax];
    uint8_t slot_in[80];
    uint16_t name_res[TXT_CAP], shortname_res[TXT_CAP], desc_res[TXT_CAP];
    // outputs
    uint32_t activated, initialized, state, wait_stopped_ok;
    uint32_t find_ran, patch_ran, resolve_ran, additem_ran;
    uint32_t removeitem_ran, gt_tid, fstring_ok, err;
    uint32_t err_step, resolve_found, resolve_override, resolve_sizex;
    uint32_t resolve_sizey, resolve_width, resolve_height, trigger_fired;
    uint32_t before_override, before_sizex, before_sizey, after_override;
    uint32_t after_sizex, after_sizey, out_remaining_item, pad2;
    uint64_t row_fname, trigger_fname;
    uint64_t before_inventory_icon, before_move_icon;
    uint64_t after_inventory_icon, after_move_icon;
    uint64_t resolve_inventory_icon, resolve_move_icon;
    double before_weight, resolve_weight;
    uint8_t out_remaining_invitem[48];
    uint8_t out_newitemslot[16];
    uint64_t reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(PatchIo) == 1872, "PatchIo layout must match the controller");

PatchIo* g_io = nullptr;
GameThreadDispatcher* g_disp = nullptr;
IGameThreadCarrier* g_carrier = nullptr;
MallocFn g_malloc = nullptr;
FreeFn g_free = nullptr;

inline uint64_t RD64(uint64_t p) { return *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(p)); }
inline int32_t RD32(uint64_t p) { return *reinterpret_cast<int32_t*>(static_cast<uintptr_t>(p)); }
inline uint8_t RD8(uint64_t p) { return *reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(p)); }
inline double RDD(uint64_t p) { return *reinterpret_cast<double*>(static_cast<uintptr_t>(p)); }
inline void WR64(uint64_t p, uint64_t v) { *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(p)) = v; }
inline void WR32(uint64_t p, int32_t v) { *reinterpret_cast<int32_t*>(static_cast<uintptr_t>(p)) = v; }
inline void WR8(uint64_t p, uint8_t v) { *reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(p)) = v; }
inline void PE(uint64_t obj, uint64_t fn, void* parms) {
    reinterpret_cast<ProcessEventFn>(static_cast<uintptr_t>(g_io->process_event))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(obj)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(fn)), parms);
}

int NameLen(const uint16_t* s) { int n = 0; while (s[n]) ++n; return n; }

bool MakeFString(unsigned char* dst16, const uint16_t* src) {
    const int len = NameLen(src);
    TCHAR* buf = static_cast<TCHAR*>(g_malloc(static_cast<size_t>(len + 1) * sizeof(TCHAR), 0u));
    if (!buf) return false;
    for (int i = 0; i < len; ++i) buf[i] = static_cast<TCHAR>(src[i]);
    buf[len] = TEXT('\0');
    *reinterpret_cast<void**>(dst16 + OFF_DATA) = buf;
    *reinterpret_cast<int32*>(dst16 + OFF_NUM) = len + 1;
    *reinterpret_cast<int32*>(dst16 + OFF_MAX) = len + 1;
    return true;
}

void FreeFStringData(unsigned char* fstr16) {
    void* data = *reinterpret_cast<void**>(fstr16 + OFF_DATA);
    if (data) g_free(data);
    *reinterpret_cast<void**>(fstr16 + OFF_DATA) = nullptr;
    *reinterpret_cast<int32*>(fstr16 + OFF_NUM) = 0;
    *reinterpret_cast<int32*>(fstr16 + OFF_MAX) = 0;
}

void CharsFromFString(const unsigned char* fstr16, uint16_t* out, int cap) {
    for (int i = 0; i < cap; ++i) out[i] = 0;
    const TCHAR* data = *reinterpret_cast<TCHAR* const*>(fstr16 + OFF_DATA);
    const int32 num = *reinterpret_cast<const int32*>(fstr16 + OFF_NUM);
    if (data && num > 0) {
        const int n = (num - 1 < cap - 1) ? num - 1 : cap - 1;
        for (int i = 0; i < n; ++i) out[i] = static_cast<uint16_t>(data[i]);
        out[n] = 0;
    }
}

uint64_t InternName(const uint16_t* src) {
    PatchIo* io = g_io;
    alignas(8) unsigned char p[24] = {};
    if (!MakeFString(p, src)) return 0;
    io->fstring_ok = 1;
    PE(io->cdo_stringlib, io->fn_conv_str_to_name, p);
    const uint64_t nm = *reinterpret_cast<uint64_t*>(p + 16);
    FreeFStringData(p);
    return nm;
}

void TextToChars(const unsigned char* src16, uint16_t* out, int cap) {
    PatchIo* io = g_io;
    for (int i = 0; i < cap; ++i) out[i] = 0;
    alignas(8) unsigned char parms[CONV_PARMS] = {};
    for (int i = 0; i < FTEXT_SIZE; ++i) parms[i] = src16[i];
    PE(io->cdo_textlib, io->fn_text_to_str, parms);
    CharsFromFString(parms + CONV_RET, out, cap);
    FreeFStringData(parms + CONV_RET);
}

void BuildInvItem(uint8_t* dst) {
    PatchIo* io = g_io;
    for (int i = 0; i < 48; ++i) dst[i] = 0;
    *reinterpret_cast<uint64_t*>(dst + IV_ID) = io->row_fname;
    *reinterpret_cast<int32_t*>(dst + IV_AMOUNT) = io->inv_amount;
    *reinterpret_cast<int32_t*>(dst + IV_QUICKBIND) = io->inv_quickbind;
    *reinterpret_cast<int32_t*>(dst + IV_ROTATED) = io->inv_rotated;
    *reinterpret_cast<int32_t*>(dst + IV_USEAMOUNT) = io->inv_useamount;
    *reinterpret_cast<int32_t*>(dst + IV_INUSE) = io->inv_inuse;
    *reinterpret_cast<float*>(dst + IV_DURABILITY) = io->inv_durability;
    *reinterpret_cast<int32_t*>(dst + IV_DECAYTIME) = io->inv_decaytime;
}

#define FAILP(code, step) do { io->err = (code); io->err_step = (step); return false; } while (0)

// The row is identified by content, not by the pointer we were handed: our icon
// texture appears in exactly one row in the whole game.
bool RowIsOurs(uint64_t row) {
    PatchIo* io = g_io;
    if (!row) FAILP(1, 1);
    if (RD64(row + io->off_inventory_icon) != io->icon_object) FAILP(2, 2);
    if (RD32(row + io->off_width) != static_cast<int32_t>(io->want_width)) FAILP(3, 3);
    if (RD32(row + io->off_height) != static_cast<int32_t>(io->want_height)) FAILP(4, 4);
    if (RDD(row + io->off_weight) != io->want_weight) FAILP(5, 5);
    return true;
}

void ReadUi(uint64_t row, uint64_t* inv, uint64_t* mov, uint32_t* ov,
            uint32_t* sx, uint32_t* sy) {
    PatchIo* io = g_io;
    *inv = RD64(row + io->off_inventory_icon);
    *mov = RD64(row + io->off_move_icon);
    *ov = RD8(row + io->off_override_flag);
    *sx = static_cast<uint32_t>(RD32(row + io->off_override_sizex));
    *sy = static_cast<uint32_t>(RD32(row + io->off_override_sizey));
}

void JobFind(void*) {
    PatchIo* io = g_io;
    io->row_fname = InternName(io->row_name);
    io->trigger_fname = InternName(io->trigger_name);
    if (!io->row_fname || !io->trigger_fname) { io->err = 10; io->find_ran = 2; return; }
    if (!RowIsOurs(io->runtime_row)) { io->find_ran = 2; return; }
    ReadUi(io->runtime_row, &io->before_inventory_icon, &io->before_move_icon,
           &io->before_override, &io->before_sizex, &io->before_sizey);
    io->before_weight = RDD(io->runtime_row + io->off_weight);
    io->find_ran = 1;
}

void JobPatch(void*) {
    PatchIo* io = g_io;
    if (io->find_ran != 1) { io->err = 20; io->patch_ran = 2; return; }
    if (!RowIsOurs(io->runtime_row)) { io->patch_ran = 2; return; }   // re-checked, not assumed

    // Three UI-only stores. InventoryIcon is rewritten with the value it already
    // holds so the two icon fields provably come from one and the same object.
    WR64(io->runtime_row + io->off_inventory_icon, io->icon_object);
    WR64(io->runtime_row + io->off_move_icon, io->icon_object);
    WR8(io->runtime_row + io->off_override_flag, 1u);
    WR32(io->runtime_row + io->off_override_sizex, static_cast<int32_t>(io->want_sizex));
    WR32(io->runtime_row + io->off_override_sizey, static_cast<int32_t>(io->want_sizey));

    ReadUi(io->runtime_row, &io->after_inventory_icon, &io->after_move_icon,
           &io->after_override, &io->after_sizex, &io->after_sizey);
    if (io->after_inventory_icon != io->icon_object ||
        io->after_move_icon != io->icon_object ||
        io->after_override != 1u ||
        io->after_sizex != io->want_sizex || io->after_sizey != io->want_sizey) {
        io->err = 21; io->err_step = 6; io->patch_ran = 2; return;
    }

    // Republish: the composite holds its own copy and will not see the edit
    // otherwise. Data-neutral for ItemList -- a name it does not contain.
    reinterpret_cast<RemoveRowFn>(static_cast<uintptr_t>(io->remove_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->item_list)), io->trigger_fname);
    io->trigger_fired = 1;
    io->patch_ran = 1;
}

void JobResolve(void*) {
    PatchIo* io = g_io;
    auto init = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->initialize_struct));
    auto destroy = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->destroy_struct));
    void* rs = reinterpret_cast<void*>(static_cast<uintptr_t>(io->row_struct));
    uint8_t* parms = static_cast<uint8_t*>(g_malloc(SG_PARMS, 0u));
    if (!parms) { io->err = 30; io->resolve_ran = 2; return; }
    for (int i = 0; i < SG_PARMS; ++i) parms[i] = 0;
    BuildInvItem(parms + SG_INVITEM);
    *reinterpret_cast<uint64_t*>(parms + SG_WORLDCTX) = io->player_inventory;
    init(rs, parms + SG_DETAILS, 1);
    PE(io->cdo_sgkfunctions, io->fn_sgk_itemdetails, parms);
    io->resolve_found = parms[SG_FOUND];
    const uint8_t* d = parms + SG_DETAILS;
    io->resolve_inventory_icon = *reinterpret_cast<const uint64_t*>(d + io->off_inventory_icon);
    io->resolve_move_icon = *reinterpret_cast<const uint64_t*>(d + io->off_move_icon);
    io->resolve_override = d[io->off_override_flag];
    io->resolve_sizex = static_cast<uint32_t>(
        *reinterpret_cast<const int32_t*>(d + io->off_override_sizex));
    io->resolve_sizey = static_cast<uint32_t>(
        *reinterpret_cast<const int32_t*>(d + io->off_override_sizey));
    io->resolve_weight = *reinterpret_cast<const double*>(d + io->off_weight);
    io->resolve_width = static_cast<uint32_t>(*reinterpret_cast<const int32_t*>(d + io->off_width));
    io->resolve_height = static_cast<uint32_t>(
        *reinterpret_cast<const int32_t*>(d + io->off_height));
    TextToChars(d + io->off_name, io->name_res, TXT_CAP);
    TextToChars(d + io->off_shortname, io->shortname_res, TXT_CAP);
    TextToChars(d + io->off_description, io->desc_res, TXT_CAP);
    destroy(rs, parms + SG_DETAILS, 1);
    g_free(parms);
    io->resolve_ran = 1;
}

void JobAddItem(void*) {
    PatchIo* io = g_io;
    alignas(8) uint8_t parms[AI_PARMS] = {};
    BuildInvItem(parms + AI_ITEM);
    parms[AI_STACKSEARCH] = 0;
    parms[AI_SHOWNOTIF] = 0;
    PE(io->player_inventory, io->fn_additem, parms);
    io->out_remaining_item = parms[AI_REMAINING];
    for (int i = 0; i < 48; ++i) io->out_remaining_invitem[i] = parms[AI_REMAINING_ITEM + i];
    for (int i = 0; i < 16; ++i) io->out_newitemslot[i] = parms[AI_NEWSLOT + i];
    io->additem_ran = 1;
}

void JobRemoveItem(void*) {
    PatchIo* io = g_io;
    alignas(8) uint8_t parms[RI_PARMS] = {};
    for (int i = 0; i < 80; ++i) parms[RI_SLOT + i] = io->slot_in[i];
    parms[RI_REMOVEWEIGHT] = 1;
    parms[RI_REMOVEAMOUNT] = 1;
    parms[RI_SPECIAL] = 0;
    PE(io->player_inventory, io->fn_removeitem, parms);
    io->removeitem_ran = 1;
}

}  // namespace

namespace Misery { namespace GameThread {
bool IsAvailable() { return g_disp && g_disp->stats().state.load() == GameThreadDispatcher::kRunning; }
bool Enqueue(JobFn fn, void* ctx) { return g_disp && g_disp->Enqueue(fn, ctx); }
}}

extern "C" __declspec(dllexport) unsigned long Init(void* param) {
    PatchIo* io = static_cast<PatchIo*>(param);
    if (!io || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
    if (!io->process_event || !io->cdo_stringlib || !io->fn_conv_str_to_name ||
        !io->cdo_textlib || !io->fn_str_to_text || !io->fn_text_to_str ||
        !io->cdo_sgkfunctions || !io->fn_sgk_itemdetails || !io->player_inventory ||
        !io->fn_additem || !io->fn_removeitem || !io->item_list || !io->master_item_list ||
        !io->runtime_table || !io->remove_row || !io->initialize_struct ||
        !io->destroy_struct || !io->row_struct || !io->runtime_row || !io->icon_object ||
        !io->fmemory_malloc || !io->fmemory_free || !io->off_inventory_icon ||
        !io->off_move_icon || !io->want_sizex || !io->want_sizey) return 0xFFFFFFFDu;
    g_io = io;
    g_malloc = reinterpret_cast<MallocFn>(static_cast<uintptr_t>(io->fmemory_malloc));
    g_free = reinterpret_cast<FreeFn>(static_cast<uintptr_t>(io->fmemory_free));
    CarrierBindings b;
    b.add_ticker = io->add_ticker; b.get_core_ticker = io->get_core_ticker;
    b.fmemory_malloc = io->fmemory_malloc;
    for (int i = 0; i < 16; ++i) {
        b.sig_add[i] = io->sig_add[i]; b.sig_get[i] = io->sig_get[i];
        b.sig_malloc[i] = io->sig_malloc[i];
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
        PatchIo* io = static_cast<PatchIo*>(p);                                     \
        if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;                       \
        return Misery::GameThread::Enqueue(&FN, nullptr) ? 0u : 1u;                 \
    }
EXPORT_JOB(RunFind, JobFind)
EXPORT_JOB(RunPatch, JobPatch)
EXPORT_JOB(RunResolve, JobResolve)
EXPORT_JOB(RunAddItem, JobAddItem)
EXPORT_JOB(RunRemoveItem, JobRemoveItem)

// Releases NOTHING: this module never owned anything. Unloading it leaves the
// first probe's table root, icon root and publication exactly as they were.
extern "C" __declspec(dllexport) unsigned long Shutdown(void* p) {
    PatchIo* io = static_cast<PatchIo*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    g_disp->Shutdown(5000);
    io->wait_stopped_ok = g_disp->wait_stopped_ok() ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    delete g_disp; g_disp = nullptr;
    Misery::Internal::DestroyCarrier(g_carrier); g_carrier = nullptr;
    return 0u;
}
