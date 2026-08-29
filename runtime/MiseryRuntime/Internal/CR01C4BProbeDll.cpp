// CR-01C4B: custom inventory icon from a mod-owned Texture2D.
//
// Everything here is the already-proven CR-01C4A path plus one new element: the
// icon. Two things about the icon are worth stating up front, because they are
// what the gate turns on.
//
// WHICH FIELD. Derived, not named: BP_InventoryItemIcon_C::UpdateIcon embeds the
// FProperty pointer of S_UIDetails::InventoryIcon and no other member of that
// struct, while BP_QuickSlot_C::UpdateItemIcon embeds QuickSlotIcon and no
// other. The target is S_ItemDetails.UIDetails + S_UIDetails.InventoryIcon.
//
// WHAT IT IS. FObjectProperty, 8 bytes -- a HARD TObjectPtr<UTexture2D>, not a
// soft reference. TObjectPtr is a plain UObject* in this build
// (UE_WITH_OBJECT_HANDLE_LATE_RESOLVE == WITH_EDITORONLY_DATA == 0), so the
// assignment is a pointer store into a row struct we own. It is NOT an opaque
// blob copied because its size happened to be known: the property type was
// resolved first and the store matches that type.
//
// LOADING is engine-native and reflected: UKismetSystemLibrary::
// LoadAsset_Blocking(TSoftObjectPtr) -> UObject*. TSoftObjectPtr is 40 bytes and
// FSoftObjectPath is 32 (measured live from the SoftObjectPath ScriptStruct),
// and FWeakObjectPtr is exactly 8, so ObjectID can only sit at offset 8 -- there
// is no slack for anything else. That arithmetic is still not trusted on its
// own: before the pointer is used, the constructed soft reference is round
// tripped back to a string through Conv_SoftObjectReferenceToString and compared
// against the path we meant, so a wrong layout fails loudly instead of loading
// something unintended.
//
// OWNERSHIP uses the SAME RuntimeAssetStore and the SAME engine root path as
// every other runtime-owned object in this project. No second lifetime
// mechanism is introduced: the texture is one more entry in the same store.
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
static constexpr int FTEXT_SIZE = 16;
static constexpr int CONV_PARMS = 32, CONV_IN = 0, CONV_RET = 16;
// TSoftObjectPtr: FWeakObjectPtr @0 (8) + FSoftObjectPath @8 (32) = 40.
// FSoftObjectPath: FTopLevelAssetPath @0 { PackageName FName @0, AssetName FName @8 },
// FString SubPathString @16.
static constexpr int SOFTPTR_SIZE = 40, SOFTPTR_PATH = 8,
                     SOFTPATH_PKG = 0, SOFTPATH_ASSET = 8, SOFTPATH_SUB = 16;
static constexpr int LOAD_PARMS = 48, LOAD_IN = 0, LOAD_RET = 40;
static constexpr int S2S_PARMS = 56, S2S_IN = 0, S2S_RET = 40;

static constexpr int IV_ID = 0, IV_AMOUNT = 8, IV_MASTERINV = 16, IV_QUICKBIND = 24,
                     IV_ROTATED = 28, IV_USEAMOUNT = 32, IV_INUSE = 36,
                     IV_DURABILITY = 40, IV_DECAYTIME = 44;
static constexpr int SD_USE_DURABILITY = 1928, SD_USE_ITEM_DECAY = 1928 + 48;
static constexpr int AI_ITEM = 0, AI_STACKSEARCH = 48, AI_SHOWNOTIF = 49,
                     AI_REMAINING = 50, AI_REMAINING_ITEM = 56, AI_NEWSLOT = 104, AI_PARMS = 120;
static constexpr int RI_SLOT = 0, RI_REMOVEWEIGHT = 80, RI_REMOVEAMOUNT = 81,
                     RI_SPECIAL = 82, RI_PARMS = 83;
static constexpr int SG_INVITEM = 0, SG_WORLDCTX = 48, SG_FOUND = 56, SG_DETAILS = 64,
                     SG_PARMS = 2336;
static constexpr int TXT_CAP = 128;
// UTexture2D dimensions, reflected offsets handed in by the controller are not
// needed: SizeX/SizeY are read via the reflected UTexture2D properties instead.

using ProcessEventFn = void(__fastcall*)(void*, void*, void*);
using MallocFn = void* (*)(size_t, uint32_t);
using FreeFn = void(__fastcall*)(void*);
using StructLifecycleFn = void(__fastcall*)(void*, void*, int32_t);
using AddRowFn = void(__fastcall*)(void*, uint64_t, const void*);
using RemoveRowFn = void(__fastcall*)(void*, uint64_t);

namespace {

constexpr uint64_t kMagic = 0x4950502D43344200ULL;  // "IPP-C4B\0"
constexpr uint32_t kProto = 1;
constexpr int kNameMax = 96;

#pragma pack(push, 1)
struct C4BIo {
    uint64_t magic; uint32_t proto; uint32_t struct_size;
    uint64_t add_ticker, get_core_ticker, fmemory_malloc, fmemory_free;
    uint8_t sig_add[16], sig_get[16], sig_malloc[16];
    uint64_t process_event, cdo_stringlib, fn_conv_str_to_name;
    uint64_t cdo_gameplaystatics, fn_spawn_object;
    uint64_t cdo_textlib, fn_str_to_text, fn_text_to_str;
    uint64_t cdo_syslib, fn_load_asset_blocking, fn_soft_to_string, texture2d_class;
    uint64_t datatable_class, transient_package, row_struct;
    uint64_t item_list, master_item_list, expected_plain_vtable;
    uint64_t expected_composite_vtable, master_class;
    uint64_t add_row, remove_row, initialize_struct, destroy_struct;
    uint64_t set_root_flags, clear_root_flags;
    uint64_t guobjectarray_objects_ptr;
    uint64_t player_inventory, fn_additem, fn_removeitem, fn_sgk_itemdetails;
    uint64_t cdo_sgkfunctions, reserved_obj;
    uint32_t off_parent_tables, off_rowstruct, off_delegate, off_inventory_array;
    uint32_t off_name, off_shortname, off_description, off_inventory_icon;
    uint32_t off_weight, off_width, off_height, off_maxstack, off_allowstacking, pad0;
    double val_weight;
    int32_t val_width, val_height, val_maxstack; uint8_t val_allowstacking; uint8_t pad1[3];
    int32_t inv_amount, inv_quickbind, inv_useamount, inv_decaytime, inv_rotated, inv_inuse;
    float inv_durability; uint32_t pad2;
    uint16_t row_name[kNameMax];
    uint16_t trigger_name[kNameMax];
    uint8_t slot_in[80];
    uint16_t name_in[TXT_CAP], shortname_in[TXT_CAP], desc_in[TXT_CAP];
    uint16_t name_row[TXT_CAP], shortname_row[TXT_CAP], desc_row[TXT_CAP];
    uint16_t name_res[TXT_CAP], shortname_res[TXT_CAP], desc_res[TXT_CAP];
    uint16_t icon_pkg_in[TXT_CAP], icon_asset_in[TXT_CAP], icon_path_roundtrip[TXT_CAP];
    uint64_t empty_textdata[3];
    uint64_t our_textdata[3];
    uint64_t row_textdata[3];
    uint64_t icon_object, icon_item_ptr, icon_class, icon_outer;
    uint64_t icon_store_handle, row_icon_ptr, resolve_icon_ptr, icon_reserved;
    uint32_t icon_size_x, icon_size_y, icon_rooted_after_acquire, icon_rooted_after_release;
    uint32_t loadicon_ran, verifyicon_ran, releaseicon_ran, soft_roundtrip_ok;
    // outputs
    uint32_t activated, initialized, state, wait_stopped_ok;
    uint32_t create_ran, populate_ran, attach_ran, detach_ran;
    uint32_t zero_ran, release_ran, resolve_ran, additem_ran;
    uint32_t removeitem_ran, gt_tid, fstring_ok, err;
    uint32_t err_step, internal_index, temp_freed, rooted_after_acquire;
    uint32_t rooted_after_release, owned_count, item_flags, table_addrow_matches;
    uint32_t table_removerow_matches, resolve_found, use_item_decay, use_durability;
    uint32_t parent_num_before, parent_max, parent_num_after_attach, parent_num_after_detach;
    uint32_t verifytext_ran, resolvetext_ran, text_fields_written, pad4;
    uint64_t table_ptr, table_item_ptr, table_class, table_outer, table_vtable;
    uint64_t table_rowstruct_after, row_fname, trigger_fname, temp_ptr, store_handle;
    uint64_t parent_data, parent_elem0, parent_elem1_before, parent_elem1_after;
    uint8_t out_remaining_invitem[48];
    uint8_t out_newitemslot[16];
    uint32_t out_remaining_item, resolve_width, resolve_height, resolve_maxstack;
    double resolve_weight; uint32_t resolve_allowstacking, pad3;
    uint64_t reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(C4BIo) == 4544, "C4BIo layout must match the controller");

C4BIo* g_io = nullptr;
GameThreadDispatcher* g_disp = nullptr;
IGameThreadCarrier* g_carrier = nullptr;
RuntimeAssetStore* g_store = nullptr;
MallocFn g_malloc = nullptr;
FreeFn g_free = nullptr;

inline uint64_t RD64(uint64_t p) { return *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(p)); }
inline int32_t RD32(uint64_t p) { return *reinterpret_cast<int32_t*>(static_cast<uintptr_t>(p)); }
inline void WR64(uint64_t p, uint64_t v) { *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(p)) = v; }
inline void WR32(uint64_t p, int32_t v) { *reinterpret_cast<int32_t*>(static_cast<uintptr_t>(p)) = v; }
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
    C4BIo* io = g_io;
    alignas(8) unsigned char p[24] = {};
    if (!MakeFString(p, src)) return 0;
    io->fstring_ok = 1;
    PE(io->cdo_stringlib, io->fn_conv_str_to_name, p);
    const uint64_t nm = *reinterpret_cast<uint64_t*>(p + 16);
    FreeFStringData(p);
    return nm;
}

bool MakeText(unsigned char* dst16, const uint16_t* src) {
    C4BIo* io = g_io;
    alignas(8) unsigned char parms[CONV_PARMS] = {};
    if (!MakeFString(parms + CONV_IN, src)) return false;
    PE(io->cdo_textlib, io->fn_str_to_text, parms);
    for (int i = 0; i < FTEXT_SIZE; ++i) dst16[i] = parms[CONV_RET + i];
    FreeFStringData(parms + CONV_IN);
    return RD64(reinterpret_cast<uint64_t>(dst16)) != 0;
}

void TextToChars(const unsigned char* src16, uint16_t* out, int cap) {
    C4BIo* io = g_io;
    for (int i = 0; i < cap; ++i) out[i] = 0;
    alignas(8) unsigned char parms[CONV_PARMS] = {};
    for (int i = 0; i < FTEXT_SIZE; ++i) parms[i] = src16[i];
    PE(io->cdo_textlib, io->fn_text_to_str, parms);
    CharsFromFString(parms + CONV_RET, out, cap);
    FreeFStringData(parms + CONV_RET);
}

uint64_t ItemForObject(uint64_t obj, uint32_t* out_index) {
    C4BIo* io = g_io;
    const int32_t idx = RD32(obj + OFF_INTERNAL_INDEX);
    if (idx < 0) return 0;
    const uint64_t chunk = RD64(io->guobjectarray_objects_ptr + static_cast<uint64_t>(idx >> 16) * 8);
    if (!chunk) return 0;
    const uint64_t item = chunk + static_cast<uint64_t>(idx & 0xFFFF) * SIZEOF_FUOBJECTITEM;
    if (RD64(item) != obj) return 0;
    if (out_index) *out_index = static_cast<uint32_t>(idx);
    return item;
}

void FireNeutralTrigger() {
    C4BIo* io = g_io;
    reinterpret_cast<RemoveRowFn>(static_cast<uintptr_t>(io->remove_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->item_list)), io->trigger_fname);
}

void BuildInvItem(uint8_t* dst) {
    C4BIo* io = g_io;
    for (int i = 0; i < 48; ++i) dst[i] = 0;
    *reinterpret_cast<uint64_t*>(dst + IV_ID) = io->row_fname;
    *reinterpret_cast<int32_t*>(dst + IV_AMOUNT) = io->inv_amount;
    *reinterpret_cast<int32_t*>(dst + IV_QUICKBIND) = io->inv_quickbind;
    dst[IV_ROTATED] = static_cast<uint8_t>(io->inv_rotated ? 1 : 0);
    *reinterpret_cast<int32_t*>(dst + IV_USEAMOUNT) = io->inv_useamount;
    dst[IV_INUSE] = static_cast<uint8_t>(io->inv_inuse ? 1 : 0);
    *reinterpret_cast<float*>(dst + IV_DURABILITY) = io->inv_durability;
    *reinterpret_cast<int32_t*>(dst + IV_DECAYTIME) = io->inv_decaytime;
}

#define FAILC(step, code) do { io->err_step = (step); io->err = (code); return false; } while (0)

bool CreateAndRoot() {
    C4BIo* io = g_io;
    alignas(8) unsigned char parms[24] = {};
    *reinterpret_cast<uint64_t*>(parms + 0) = io->datatable_class;
    *reinterpret_cast<uint64_t*>(parms + 8) = io->transient_package;
    PE(io->cdo_gameplaystatics, io->fn_spawn_object, parms);
    const uint64_t obj = *reinterpret_cast<uint64_t*>(parms + 16);
    if (!obj) FAILC(1, 1);
    io->table_ptr = obj;
    io->table_class = RD64(obj + OFF_CLASS_PRIVATE);
    io->table_outer = RD64(obj + OFF_OUTER_PRIVATE);
    io->table_vtable = RD64(obj);
    if (io->table_class != io->datatable_class) FAILC(2, 2);
    if (io->table_outer != io->transient_package) FAILC(2, 3);
    if (io->table_vtable != io->expected_plain_vtable) FAILC(2, 4);
    const uint64_t item = ItemForObject(obj, &io->internal_index);
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
    if (RD64(obj + io->off_rowstruct) != io->row_struct) FAILC(5, 8);
    io->table_rowstruct_after = io->row_struct;
    const uint64_t vt = io->table_vtable;
    io->table_addrow_matches = (RD64(vt + 95 * 8) == io->add_row) ? 1u : 0u;
    io->table_removerow_matches = (RD64(vt + 94 * 8) == io->remove_row) ? 1u : 0u;
    if (!io->table_addrow_matches || !io->table_removerow_matches) FAILC(6, 9);
    io->row_fname = InternName(io->row_name);
    if (!io->row_fname) FAILC(7, 10);
    io->trigger_fname = InternName(io->trigger_name);
    if (!io->trigger_fname || io->trigger_fname == io->row_fname) FAILC(7, 11);
    return true;
}

void JobCreate(void*) {
    C4BIo* io = g_io;
    io->gt_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    io->create_ran = CreateAndRoot() ? 1u : 2u;
}

// Load the mod-owned Texture2D through the reflected engine loader, then take
// ownership of it in the SAME store as everything else.
bool LoadIcon() {
    C4BIo* io = g_io;
    const uint64_t pkg = InternName(io->icon_pkg_in);
    const uint64_t asset = InternName(io->icon_asset_in);
    if (!pkg || !asset) FAILC(20, 60);

    alignas(8) uint8_t soft[SOFTPTR_SIZE] = {};
    *reinterpret_cast<uint64_t*>(soft + SOFTPTR_PATH + SOFTPATH_PKG) = pkg;
    *reinterpret_cast<uint64_t*>(soft + SOFTPTR_PATH + SOFTPATH_ASSET) = asset;
    // SubPathString stays a zeroed FString: empty, which is its valid null state.

    // Self-check the layout BEFORE using it: round the soft reference back to a
    // string through the engine and let the controller compare it with the path
    // we meant. A wrong offset shows up here rather than as a mystery load.
    {
        alignas(8) uint8_t p[S2S_PARMS] = {};
        for (int i = 0; i < SOFTPTR_SIZE; ++i) p[S2S_IN + i] = soft[i];
        PE(io->cdo_syslib, io->fn_soft_to_string, p);
        CharsFromFString(p + S2S_RET, io->icon_path_roundtrip, TXT_CAP);
        FreeFStringData(p + S2S_RET);
    }
    if (io->icon_path_roundtrip[0] == 0) FAILC(21, 61);

    alignas(8) uint8_t lp[LOAD_PARMS] = {};
    for (int i = 0; i < SOFTPTR_SIZE; ++i) lp[LOAD_IN + i] = soft[i];
    PE(io->cdo_syslib, io->fn_load_asset_blocking, lp);
    const uint64_t obj = *reinterpret_cast<uint64_t*>(lp + LOAD_RET);
    if (!obj) FAILC(22, 62);
    io->icon_object = obj;
    io->icon_class = RD64(obj + OFF_CLASS_PRIVATE);
    io->icon_outer = RD64(obj + OFF_OUTER_PRIVATE);
    if (io->icon_class != io->texture2d_class) FAILC(23, 63);

    const uint64_t item = ItemForObject(obj, nullptr);
    if (!item) FAILC(24, 64);
    io->icon_item_ptr = item;
    io->icon_store_handle = g_store->Acquire(reinterpret_cast<void*>(static_cast<uintptr_t>(obj)),
                                             reinterpret_cast<void*>(static_cast<uintptr_t>(item)));
    if (!io->icon_store_handle) FAILC(25, 65);
    io->icon_rooted_after_acquire =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(obj))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    if (!io->icon_rooted_after_acquire) FAILC(25, 66);
    return true;
}

void JobLoadIcon(void*) { C4BIo* io = g_io; io->loadicon_ran = LoadIcon() ? 1u : 2u; }

void JobPopulate(void*) {
    C4BIo* io = g_io;
    if (!io->table_ptr || io->create_ran != 1) { io->err = 20; io->populate_ran = 2; return; }
    if (!io->icon_object || io->loadicon_ran != 1) { io->err = 21; io->populate_ran = 2; return; }
    void* rs = reinterpret_cast<void*>(static_cast<uintptr_t>(io->row_struct));
    auto init = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->initialize_struct));
    auto destroy = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->destroy_struct));
    uint8_t* temp = static_cast<uint8_t*>(g_malloc(io->struct_size, 0u));
    if (!temp) { io->err = 23; io->populate_ran = 2; return; }
    io->temp_ptr = reinterpret_cast<uint64_t>(temp);
    init(rs, temp, 1);
    io->use_durability = temp[SD_USE_DURABILITY];
    io->use_item_decay = temp[SD_USE_ITEM_DECAY];

    const uint32_t toff[3] = {io->off_name, io->off_shortname, io->off_description};
    for (int i = 0; i < 3; ++i) io->empty_textdata[i] = RD64(io->temp_ptr + toff[i]);
    const uint16_t* tin[3] = {io->name_in, io->shortname_in, io->desc_in};
    uint32_t written = 0;
    for (int i = 0; i < 3; ++i) {
        alignas(8) unsigned char t[FTEXT_SIZE] = {};
        if (!MakeText(t, tin[i])) { io->err = 24; io->populate_ran = 2; g_free(temp); return; }
        for (int b = 0; b < FTEXT_SIZE; ++b) temp[toff[i] + b] = t[b];
        io->our_textdata[i] = RD64(io->temp_ptr + toff[i]);
        ++written;
    }
    io->text_fields_written = written;

    *reinterpret_cast<double*>(temp + io->off_weight) = io->val_weight;
    *reinterpret_cast<int32_t*>(temp + io->off_width) = io->val_width;
    *reinterpret_cast<int32_t*>(temp + io->off_height) = io->val_height;
    *reinterpret_cast<int32_t*>(temp + io->off_maxstack) = io->val_maxstack;
    *reinterpret_cast<uint8_t*>(temp + io->off_allowstacking) = io->val_allowstacking;
    // The icon: a HARD TObjectPtr<UTexture2D>. Plain pointer store, matching the
    // resolved property type. The referent is already a registered GC root.
    *reinterpret_cast<uint64_t*>(temp + io->off_inventory_icon) = io->icon_object;

    reinterpret_cast<AddRowFn>(static_cast<uintptr_t>(io->add_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr)), io->row_fname, temp);
    destroy(rs, temp, 1);
    g_free(temp);
    io->temp_freed = 1;
    io->populate_ran = 1;
}

void JobVerifyRow(void*) {
    C4BIo* io = g_io;
    if (!io->temp_freed) { io->err = 30; io->verifytext_ran = 2; return; }
    const uint64_t row = *reinterpret_cast<uint64_t*>(io->slot_in);
    if (!row) { io->err = 31; io->verifytext_ran = 2; return; }
    const uint32_t toff[3] = {io->off_name, io->off_shortname, io->off_description};
    uint16_t* outs[3] = {io->name_row, io->shortname_row, io->desc_row};
    for (int i = 0; i < 3; ++i) {
        io->row_textdata[i] = RD64(row + toff[i]);
        TextToChars(reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(row + toff[i])),
                    outs[i], TXT_CAP);
    }
    io->row_icon_ptr = RD64(row + io->off_inventory_icon);
    io->verifytext_ran = 1;
    io->verifyicon_ran = (io->row_icon_ptr == io->icon_object) ? 1u : 2u;
}

bool Attach() {
    C4BIo* io = g_io;
    const uint64_t master = io->master_item_list;
    if (RD64(master) != io->expected_composite_vtable) FAILC(10, 30);
    if (RD64(master + OFF_CLASS_PRIVATE) != io->master_class) FAILC(10, 31);
    if (RD64(master + io->off_rowstruct) != io->row_struct) FAILC(10, 32);
    const uint64_t pt = master + io->off_parent_tables;
    const uint64_t data = RD64(pt + OFF_DATA);
    const int32_t num = RD32(pt + OFF_NUM), maxn = RD32(pt + OFF_MAX);
    io->parent_data = data; io->parent_num_before = static_cast<uint32_t>(num);
    io->parent_max = static_cast<uint32_t>(maxn);
    if (!data) FAILC(11, 33);
    if (num != 1) FAILC(11, 34);
    if (maxn - num < 1) FAILC(11, 35);
    io->parent_elem0 = RD64(data + 0);
    io->parent_elem1_before = RD64(data + 8);
    if (io->parent_elem0 != io->item_list) FAILC(11, 36);
    if (io->parent_elem1_before != 0) FAILC(11, 37);
    if (!g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr)))) FAILC(12, 39);
    if (RD64(io->table_ptr + io->off_rowstruct) != io->row_struct) FAILC(12, 40);
    if (RD64(io->table_ptr) != io->expected_plain_vtable) FAILC(12, 41);
    WR64(data + 8, io->table_ptr);
    WR32(pt + OFF_NUM, 2);
    io->parent_num_after_attach = static_cast<uint32_t>(RD32(pt + OFF_NUM));
    io->parent_elem1_after = RD64(data + 8);
    if (io->parent_num_after_attach != 2 || io->parent_elem1_after != io->table_ptr) FAILC(13, 42);
    FireNeutralTrigger();
    return true;
}

void JobAttach(void*) { C4BIo* io = g_io; io->attach_ran = Attach() ? 1u : 2u; }

void JobResolve(void*) {
    C4BIo* io = g_io;
    auto init = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->initialize_struct));
    auto destroy = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->destroy_struct));
    void* rs = reinterpret_cast<void*>(static_cast<uintptr_t>(io->row_struct));
    uint8_t* parms = static_cast<uint8_t*>(g_malloc(SG_PARMS, 0u));
    if (!parms) { io->err = 81; io->resolve_ran = 2; return; }
    for (int i = 0; i < SG_PARMS; ++i) parms[i] = 0;
    BuildInvItem(parms + SG_INVITEM);
    *reinterpret_cast<uint64_t*>(parms + SG_WORLDCTX) = io->player_inventory;
    init(rs, parms + SG_DETAILS, 1);
    PE(io->cdo_sgkfunctions, io->fn_sgk_itemdetails, parms);
    io->resolve_found = parms[SG_FOUND];
    const uint8_t* d = parms + SG_DETAILS;
    io->resolve_weight = *reinterpret_cast<const double*>(d + io->off_weight);
    io->resolve_width = static_cast<uint32_t>(*reinterpret_cast<const int32_t*>(d + io->off_width));
    io->resolve_height = static_cast<uint32_t>(*reinterpret_cast<const int32_t*>(d + io->off_height));
    io->resolve_maxstack = static_cast<uint32_t>(*reinterpret_cast<const int32_t*>(d + io->off_maxstack));
    io->resolve_allowstacking = d[io->off_allowstacking];
    io->resolve_icon_ptr = *reinterpret_cast<const uint64_t*>(d + io->off_inventory_icon);
    TextToChars(d + io->off_name, io->name_res, TXT_CAP);
    TextToChars(d + io->off_shortname, io->shortname_res, TXT_CAP);
    TextToChars(d + io->off_description, io->desc_res, TXT_CAP);
    io->resolvetext_ran = 1;
    destroy(rs, parms + SG_DETAILS, 1);
    g_free(parms);
    io->resolve_ran = 1;
}

void JobAddItem(void*) {
    C4BIo* io = g_io;
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
    C4BIo* io = g_io;
    if (io->slot_in[0] != 1) { io->err = 101; io->removeitem_ran = 2; return; }
    if (*reinterpret_cast<uint64_t*>(io->slot_in + 24 + IV_ID) != io->row_fname) {
        io->err = 102; io->removeitem_ran = 2; return;
    }
    alignas(8) uint8_t parms[RI_PARMS] = {};
    for (int i = 0; i < 80; ++i) parms[RI_SLOT + i] = io->slot_in[i];
    parms[RI_REMOVEWEIGHT] = 1;
    parms[RI_REMOVEAMOUNT] = 1;
    parms[RI_SPECIAL] = 0;
    PE(io->player_inventory, io->fn_removeitem, parms);
    io->removeitem_ran = 1;
}

void JobDetach(void*) {
    C4BIo* io = g_io;
    const uint64_t pt = io->master_item_list + io->off_parent_tables;
    const uint64_t data = RD64(pt + OFF_DATA);
    if (!data || data != io->parent_data) { io->err = 50; io->detach_ran = 2; return; }
    if (RD32(pt + OFF_NUM) != 2) { io->err = 51; io->detach_ran = 2; return; }
    WR32(pt + OFF_NUM, 1);
    io->parent_num_after_detach = static_cast<uint32_t>(RD32(pt + OFF_NUM));
    FireNeutralTrigger();
    io->detach_ran = 1;
}

void JobZeroSlot(void*) {
    C4BIo* io = g_io;
    const uint64_t pt = io->master_item_list + io->off_parent_tables;
    const uint64_t data = RD64(pt + OFF_DATA);
    if (!data || data != io->parent_data) { io->err = 60; io->zero_ran = 2; return; }
    if (RD32(pt + OFF_NUM) != 1) { io->err = 61; io->zero_ran = 2; return; }
    WR64(data + 8, 0);
    io->zero_ran = (RD64(data + 8) == 0) ? 1u : 2u;
}

void JobRemoveRow(void*) {
    C4BIo* io = g_io;
    reinterpret_cast<RemoveRowFn>(static_cast<uintptr_t>(io->remove_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr)), io->row_fname);
}

// Release the icon FIRST is wrong: the row still references it until the row is
// gone. The controller therefore removes the row, detaches, and only then calls
// this.
void JobReleaseIcon(void*) {
    C4BIo* io = g_io;
    if (!io->icon_store_handle) { io->err = 70; io->releaseicon_ran = 2; return; }
    const bool ok = g_store->Release(io->icon_store_handle);
    io->icon_rooted_after_release =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(io->icon_object))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    io->releaseicon_ran = ok ? 1u : 2u;
}

void JobRelease(void*) {
    C4BIo* io = g_io;
    if (!io->store_handle) { io->err = 71; io->release_ran = 2; return; }
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
    C4BIo* io = static_cast<C4BIo*>(param);
    if (!io || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
    if (!io->process_event || !io->cdo_stringlib || !io->fn_conv_str_to_name ||
        !io->cdo_gameplaystatics || !io->fn_spawn_object || !io->cdo_textlib ||
        !io->fn_str_to_text || !io->fn_text_to_str || !io->cdo_syslib ||
        !io->fn_load_asset_blocking || !io->fn_soft_to_string || !io->texture2d_class ||
        !io->datatable_class || !io->transient_package || !io->row_struct || !io->item_list ||
        !io->master_item_list || !io->expected_plain_vtable || !io->expected_composite_vtable ||
        !io->master_class || !io->add_row || !io->remove_row || !io->initialize_struct ||
        !io->destroy_struct || !io->set_root_flags || !io->clear_root_flags ||
        !io->guobjectarray_objects_ptr || !io->player_inventory || !io->fn_additem ||
        !io->fn_removeitem || !io->fn_sgk_itemdetails || !io->cdo_sgkfunctions ||
        !io->fmemory_malloc || !io->fmemory_free || !io->off_parent_tables ||
        !io->off_rowstruct || !io->off_inventory_icon) return 0xFFFFFFFDu;
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
        C4BIo* io = static_cast<C4BIo*>(p);                                         \
        if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;                       \
        return Misery::GameThread::Enqueue(&FN, nullptr) ? 0u : 1u;                 \
    }
EXPORT_JOB(RunCreate, JobCreate)
EXPORT_JOB(RunLoadIcon, JobLoadIcon)
EXPORT_JOB(RunPopulate, JobPopulate)
EXPORT_JOB(RunVerifyRow, JobVerifyRow)
EXPORT_JOB(RunAttach, JobAttach)
EXPORT_JOB(RunResolve, JobResolve)
EXPORT_JOB(RunAddItem, JobAddItem)
EXPORT_JOB(RunRemoveItem, JobRemoveItem)
EXPORT_JOB(RunRemoveRow, JobRemoveRow)
EXPORT_JOB(RunDetach, JobDetach)
EXPORT_JOB(RunZeroSlot, JobZeroSlot)
EXPORT_JOB(RunReleaseIcon, JobReleaseIcon)
EXPORT_JOB(RunRelease, JobRelease)

extern "C" __declspec(dllexport) unsigned long Shutdown(void* p) {
    C4BIo* io = static_cast<C4BIo*>(p);
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
