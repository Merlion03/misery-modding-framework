// CR-01C5: a runtime-defined item with a real 3D world representation.
//
// This is the CR-01C4B probe plus the world fields that CR-01C5 phase 1 traced,
// and it is a superset rather than a rewrite because every mechanism it reuses
// was already proven: the runtime UDataTable, the RuntimeAssetStore root path,
// the reflected LoadAsset_Blocking loader, engine AddRow/RemoveRow, the
// data-neutral publication trigger and BP_MasterInventory_C::AddItem.
//
// WHAT PHASE 1 ESTABLISHED, and what this therefore writes:
//
//   WorldClass  -- an FClassProperty whose MetaClass is Actor. It is the class
//                  handed to BeginDeferredActorSpawnFromClass, and
//                  BP_PlayerInventory_C::SpawnDroppedItem hard-gates on
//                  IsValidClass(WorldClass), printing "ERROR :: Item has no
//                  World Item class set in the ItemList" when it fails. We
//                  point it at the VANILLA BP_StaticMasterItem_C, which 472 of
//                  496 vanilla rows already use. Referencing a vanilla class is
//                  not copying a vanilla asset, and it is what keeps the
//                  unproven custom-Blueprint-parent problem off this path.
//
//   StaticMesh  -- an FSoftObjectProperty. BP_StaticMasterItem_C loads it
//                  ITSELF: UserConstructionScript does LoadAsset_Blocking on it,
//                  casts to UStaticMesh and calls SetStaticMesh, and the
//                  replicated path repeats that asynchronously through
//                  Mesh -> OnRep_Mesh. So the mesh must be reachable by SOFT
//                  PATH, which is what the mounted container provides. The 40
//                  byte layout is the one CR-01C4B round-tripped through
//                  Conv_SoftObjectReferenceToString before trusting it:
//                  FWeakObjectPtr @0, then FSoftObjectPath @8 as
//                  { FName PackageName @0, FName AssetName @8, FString @16 }.
//                  Only the two FNames are written; the FString is left alone.
//
//   ItemOffsets -- struct Transform, and the reason it is written EXPLICITLY
//                  rather than left to InitializeStruct: Scale3D sits at +64
//                  (Rotation @0 size 32, Translation @32 size 24), so a zeroed
//                  transform is scale (0,0,0) and an invisible mesh. Vanilla
//                  1x1 rows read identity rotation and scale (1,1,1).
//
// The mesh is also loaded and rooted here, through the SAME RuntimeAssetStore
// as the icon. Strictly the row only holds a soft reference and the game would
// load the mesh on demand, but owning it keeps it resident and introduces no
// second lifetime mechanism -- it is one more entry in the same store.
#define C5IO_EXPECTED_SIZE 5648
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

constexpr uint64_t kMagic = 0x4950502D43350000ULL;  // "IPP-C5\0\0"
constexpr uint32_t kProto = 1;
constexpr int kNameMax = 96;

#pragma pack(push, 1)
struct C5Io {
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
    // --- CR-01C5 world representation inputs ---
    uint64_t staticmesh_class, world_class, actor_class, c5_pad0;
    uint32_t off_move_icon, off_override_flag, off_override_sizey, off_override_sizex;
    uint32_t off_worldclass, off_staticmesh, off_itemoffsets, off_rot;
    uint32_t off_trans, off_scale, want_sizex, want_sizey;
    double want_scale_x, want_scale_y, want_scale_z;
    double want_trans_x, want_trans_y, want_trans_z;
    uint16_t mesh_pkg_in[TXT_CAP], mesh_asset_in[TXT_CAP], mesh_path_roundtrip[TXT_CAP];
    // outputs
    uint32_t activated, initialized, state, wait_stopped_ok;
    uint32_t create_ran, populate_ran, attach_ran, detach_ran;
    uint32_t zero_ran, release_ran, resolve_ran, additem_ran;
    uint32_t removeitem_ran, gt_tid, fstring_ok, err;
    uint32_t err_step, internal_index, temp_freed, rooted_after_acquire;
    uint32_t rooted_after_release, owned_count, item_flags, table_addrow_matches;
    uint32_t table_removerow_matches, resolve_found, use_item_decay, use_durability;
    uint32_t parent_num_before, parent_max, parent_num_after_attach, parent_num_after_detach;
    uint32_t verifytext_ran, resolvetext_ran, text_fields_written, internrow_ran;
    uint64_t table_ptr, table_item_ptr, table_class, table_outer, table_vtable;
    uint64_t table_rowstruct_after, row_fname, trigger_fname, temp_ptr, store_handle;
    uint64_t parent_data, parent_elem0, parent_elem1_before, parent_elem1_after;
    uint8_t out_remaining_invitem[48];
    uint8_t out_newitemslot[16];
    uint32_t out_remaining_item, resolve_width, resolve_height, resolve_maxstack;
    double resolve_weight; uint32_t resolve_allowstacking, pad3;
    // --- CR-01C5 world representation outputs ---
    uint64_t mesh_object, mesh_item_ptr, mesh_class, mesh_store_handle;
    uint64_t mesh_pkg_name, mesh_asset_name;
    uint64_t row_move_icon, row_worldclass, resolve_worldclass, c5_pad1;
    uint32_t loadmesh_ran, verifymesh_ran, releasemesh_ran, mesh_soft_roundtrip_ok;
    uint32_t mesh_rooted_after_acquire, mesh_rooted_after_release, row_override, row_sizex;
    uint32_t row_sizey, resolve_override, resolve_sizex, resolve_sizey;
    double row_scale_x, row_scale_y, row_scale_z;
    double resolve_scale_x, resolve_scale_y, resolve_scale_z;
    uint64_t row_staticmesh_pkg, row_staticmesh_asset;
    uint64_t resolve_staticmesh_pkg, resolve_staticmesh_asset;
    uint64_t reserved[2];
};
#pragma pack(pop)
static_assert(sizeof(C5Io) == C5IO_EXPECTED_SIZE, "C5Io layout must match the controller");

C5Io* g_io = nullptr;
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
    C5Io* io = g_io;
    alignas(8) unsigned char p[24] = {};
    if (!MakeFString(p, src)) return 0;
    io->fstring_ok = 1;
    PE(io->cdo_stringlib, io->fn_conv_str_to_name, p);
    const uint64_t nm = *reinterpret_cast<uint64_t*>(p + 16);
    FreeFStringData(p);
    return nm;
}

bool MakeText(unsigned char* dst16, const uint16_t* src) {
    C5Io* io = g_io;
    alignas(8) unsigned char parms[CONV_PARMS] = {};
    if (!MakeFString(parms + CONV_IN, src)) return false;
    PE(io->cdo_textlib, io->fn_str_to_text, parms);
    for (int i = 0; i < FTEXT_SIZE; ++i) dst16[i] = parms[CONV_RET + i];
    FreeFStringData(parms + CONV_IN);
    return RD64(reinterpret_cast<uint64_t>(dst16)) != 0;
}

void TextToChars(const unsigned char* src16, uint16_t* out, int cap) {
    C5Io* io = g_io;
    for (int i = 0; i < cap; ++i) out[i] = 0;
    alignas(8) unsigned char parms[CONV_PARMS] = {};
    for (int i = 0; i < FTEXT_SIZE; ++i) parms[i] = src16[i];
    PE(io->cdo_textlib, io->fn_text_to_str, parms);
    CharsFromFString(parms + CONV_RET, out, cap);
    FreeFStringData(parms + CONV_RET);
}

uint64_t ItemForObject(uint64_t obj, uint32_t* out_index) {
    C5Io* io = g_io;
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
    C5Io* io = g_io;
    reinterpret_cast<RemoveRowFn>(static_cast<uintptr_t>(io->remove_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->item_list)), io->trigger_fname);
}

void BuildInvItem(uint8_t* dst) {
    C5Io* io = g_io;
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

// STRUCTURED ERRORS.  `err` used to be a bare number, and the numbers collided:
// 30/31 meant "composite vtable/class mismatch" in Attach AND "temp not freed /
// null row" in JobVerifyRow; 60/61 meant "icon FName intern failed / round-trip
// empty" in LoadIcon AND "ParentTables Data moved / Num != 1" in JobZeroSlot.
// The value alone was ambiguous -- it could only be disambiguated by noticing
// which *_ran field happened to be 2.
//
// So an error is now (subsystem << 8) | code. The low byte keeps its historical
// meaning, so every code recorded in past evidence still reads the same; the
// high byte says which job produced it. 0 stays "no error".
enum : uint32_t {
    SUB_INIT       = 0x01,
    SUB_CREATE     = 0x02,
    SUB_LOADICON   = 0x03,
    SUB_LOADMESH   = 0x04,
    SUB_POPULATE   = 0x05,
    SUB_VERIFYROW  = 0x06,
    SUB_ATTACH     = 0x07,
    SUB_RESOLVE    = 0x08,
    SUB_REMOVEITEM = 0x09,
    SUB_DETACH     = 0x0A,
    SUB_ZEROSLOT   = 0x0B,
    SUB_RELEASE    = 0x0C,
};
#define MERR(sub, code) ((static_cast<uint32_t>(sub) << 8) | static_cast<uint32_t>(code))

// Every job clears both error fields on entry. Without this a job that succeeds
// still reports whatever `err` the previous job left behind, which is how a
// clean release could be reported next to a stale failure code.
#define JOB_ENTER() do { io->err = 0u; io->err_step = 0u; } while (0)

#define FAILC(sub, step, code) \
    do { io->err_step = (step); io->err = MERR((sub), (code)); return false; } while (0)

bool CreateAndRoot() {
    C5Io* io = g_io;
    alignas(8) unsigned char parms[24] = {};
    *reinterpret_cast<uint64_t*>(parms + 0) = io->datatable_class;
    *reinterpret_cast<uint64_t*>(parms + 8) = io->transient_package;
    PE(io->cdo_gameplaystatics, io->fn_spawn_object, parms);
    const uint64_t obj = *reinterpret_cast<uint64_t*>(parms + 16);
    if (!obj) FAILC(SUB_CREATE, 1, 1);
    io->table_ptr = obj;
    io->table_class = RD64(obj + OFF_CLASS_PRIVATE);
    io->table_outer = RD64(obj + OFF_OUTER_PRIVATE);
    io->table_vtable = RD64(obj);
    if (io->table_class != io->datatable_class) FAILC(SUB_CREATE, 2, 2);
    if (io->table_outer != io->transient_package) FAILC(SUB_CREATE, 2, 3);
    if (io->table_vtable != io->expected_plain_vtable) FAILC(SUB_CREATE, 2, 4);
    const uint64_t item = ItemForObject(obj, &io->internal_index);
    if (!item) FAILC(SUB_CREATE, 3, 5);
    io->table_item_ptr = item;
    io->store_handle = g_store->Acquire(reinterpret_cast<void*>(static_cast<uintptr_t>(obj)),
                                        reinterpret_cast<void*>(static_cast<uintptr_t>(item)));
    if (!io->store_handle) FAILC(SUB_CREATE, 4, 6);
    io->item_flags = static_cast<uint32_t>(RD32(item + 8));
    io->rooted_after_acquire =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(obj))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    if (!io->rooted_after_acquire) FAILC(SUB_CREATE, 4, 7);
    WR64(obj + io->off_rowstruct, io->row_struct);
    if (RD64(obj + io->off_rowstruct) != io->row_struct) FAILC(SUB_CREATE, 5, 8);
    io->table_rowstruct_after = io->row_struct;
    const uint64_t vt = io->table_vtable;
    io->table_addrow_matches = (RD64(vt + 95 * 8) == io->add_row) ? 1u : 0u;
    io->table_removerow_matches = (RD64(vt + 94 * 8) == io->remove_row) ? 1u : 0u;
    if (!io->table_addrow_matches || !io->table_removerow_matches) FAILC(SUB_CREATE, 6, 9);
    io->row_fname = InternName(io->row_name);
    if (!io->row_fname) FAILC(SUB_CREATE, 7, 10);
    io->trigger_fname = InternName(io->trigger_name);
    if (!io->trigger_fname || io->trigger_fname == io->row_fname) FAILC(SUB_CREATE, 7, 11);
    return true;
}

void JobCreate(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    io->gt_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    io->create_ran = CreateAndRoot() ? 1u : 2u;
}

// Load the mod-owned Texture2D through the reflected engine loader, then take
// ownership of it in the SAME store as everything else.
bool LoadIcon() {
    C5Io* io = g_io;
    const uint64_t pkg = InternName(io->icon_pkg_in);
    const uint64_t asset = InternName(io->icon_asset_in);
    if (!pkg || !asset) FAILC(SUB_LOADICON, 20, 60);

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
    if (io->icon_path_roundtrip[0] == 0) FAILC(SUB_LOADICON, 21, 61);

    alignas(8) uint8_t lp[LOAD_PARMS] = {};
    for (int i = 0; i < SOFTPTR_SIZE; ++i) lp[LOAD_IN + i] = soft[i];
    PE(io->cdo_syslib, io->fn_load_asset_blocking, lp);
    const uint64_t obj = *reinterpret_cast<uint64_t*>(lp + LOAD_RET);
    if (!obj) FAILC(SUB_LOADICON, 22, 62);
    io->icon_object = obj;
    io->icon_class = RD64(obj + OFF_CLASS_PRIVATE);
    io->icon_outer = RD64(obj + OFF_OUTER_PRIVATE);
    if (io->icon_class != io->texture2d_class) FAILC(SUB_LOADICON, 23, 63);

    const uint64_t item = ItemForObject(obj, nullptr);
    if (!item) FAILC(SUB_LOADICON, 24, 64);
    io->icon_item_ptr = item;
    io->icon_store_handle = g_store->Acquire(reinterpret_cast<void*>(static_cast<uintptr_t>(obj)),
                                             reinterpret_cast<void*>(static_cast<uintptr_t>(item)));
    if (!io->icon_store_handle) FAILC(SUB_LOADICON, 25, 65);
    io->icon_rooted_after_acquire =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(obj))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    if (!io->icon_rooted_after_acquire) FAILC(SUB_LOADICON, 25, 66);
    return true;
}

void JobLoadIcon(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    io->loadicon_ran = LoadIcon() ? 1u : 2u;
}

// Same proven loader as the icon, with the class check pointed at UStaticMesh.
// The soft reference is round-tripped back to a string through the engine before
// the returned pointer is trusted, exactly as CR-01C4B did.
bool LoadMesh() {
    C5Io* io = g_io;
    const uint64_t pkg = InternName(io->mesh_pkg_in);
    const uint64_t asset = InternName(io->mesh_asset_in);
    if (!pkg || !asset) FAILC(SUB_LOADMESH, 40, 80);
    io->mesh_pkg_name = pkg;
    io->mesh_asset_name = asset;
    alignas(8) uint8_t soft[SOFTPTR_SIZE] = {};
    *reinterpret_cast<uint64_t*>(soft + SOFTPTR_PATH + SOFTPATH_PKG) = pkg;
    *reinterpret_cast<uint64_t*>(soft + SOFTPTR_PATH + SOFTPATH_ASSET) = asset;
    { alignas(8) uint8_t p[S2S_PARMS] = {};
      for (int i = 0; i < SOFTPTR_SIZE; ++i) p[S2S_IN + i] = soft[i];
      PE(io->cdo_syslib, io->fn_soft_to_string, p);
      CharsFromFString(p + S2S_RET, io->mesh_path_roundtrip, TXT_CAP);
      FreeFStringData(p + S2S_RET); }
    if (io->mesh_path_roundtrip[0] == 0) FAILC(SUB_LOADMESH, 41, 81);
    io->mesh_soft_roundtrip_ok = 1;
    alignas(8) uint8_t lp[LOAD_PARMS] = {};
    for (int i = 0; i < SOFTPTR_SIZE; ++i) lp[LOAD_IN + i] = soft[i];
    PE(io->cdo_syslib, io->fn_load_asset_blocking, lp);
    const uint64_t obj = *reinterpret_cast<uint64_t*>(lp + LOAD_RET);
    if (!obj) FAILC(SUB_LOADMESH, 42, 82);
    io->mesh_object = obj;
    io->mesh_class = RD64(obj + OFF_CLASS_PRIVATE);
    if (io->mesh_class != io->staticmesh_class) FAILC(SUB_LOADMESH, 43, 83);
    const uint64_t item = ItemForObject(obj, nullptr);
    if (!item) FAILC(SUB_LOADMESH, 44, 84);
    io->mesh_item_ptr = item;
    io->mesh_store_handle = g_store->Acquire(
        reinterpret_cast<void*>(static_cast<uintptr_t>(obj)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(item)));
    if (!io->mesh_store_handle) FAILC(SUB_LOADMESH, 45, 85);
    io->mesh_rooted_after_acquire =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(obj))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    if (!io->mesh_rooted_after_acquire) FAILC(SUB_LOADMESH, 46, 86);
    return true;
}

void JobLoadMesh(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    io->loadmesh_ran = LoadMesh() ? 1u : 2u;
}

void JobPopulate(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    if (!io->table_ptr || io->create_ran != 1) { io->err = MERR(SUB_POPULATE, 20); io->populate_ran = 2; return; }
    if (!io->icon_object || io->loadicon_ran != 1) { io->err = MERR(SUB_POPULATE, 21); io->populate_ran = 2; return; }
    if (!io->mesh_object || io->loadmesh_ran != 1) { io->err = MERR(SUB_POPULATE, 22); io->populate_ran = 2; return; }
    if (!io->world_class) { io->err = MERR(SUB_POPULATE, 25); io->populate_ran = 2; return; }
    void* rs = reinterpret_cast<void*>(static_cast<uintptr_t>(io->row_struct));
    auto init = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->initialize_struct));
    auto destroy = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->destroy_struct));
    uint8_t* temp = static_cast<uint8_t*>(g_malloc(io->struct_size, 0u));
    if (!temp) { io->err = MERR(SUB_POPULATE, 23); io->populate_ran = 2; return; }
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
        if (!MakeText(t, tin[i])) {
            // DESTROY BEFORE FREE. `temp` has been through InitializeStruct, so
            // its nested FStrings, TArrays and FTexts own heap allocations and
            // refcounts; and any text already moved in on an earlier iteration
            // is owned here too. Freeing the bytes without destructing leaked
            // all of it. This path had never fired, so it was untested as well
            // as wrong.
            io->err = MERR(SUB_POPULATE, 24);
            io->populate_ran = 2;
            destroy(rs, temp, 1);
            g_free(temp);
            io->temp_freed = 1;
            return;
        }
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
    // The drag ghost reads a DIFFERENT field; 496 of 496 vanilla rows set it to
    // the same texture as InventoryIcon (CR-01C4B).
    *reinterpret_cast<uint64_t*>(temp + io->off_move_icon) = io->icon_object;
    *reinterpret_cast<uint8_t*>(temp + io->off_override_flag) = 1u;
    *reinterpret_cast<int32_t*>(temp + io->off_override_sizex) =
        static_cast<int32_t>(io->want_sizex);
    *reinterpret_cast<int32_t*>(temp + io->off_override_sizey) =
        static_cast<int32_t>(io->want_sizey);

    // WorldClass: a plain UClass* store into an FClassProperty. Without it
    // SpawnDroppedItem prints its "no World Item class" error and spawns nothing.
    *reinterpret_cast<uint64_t*>(temp + io->off_worldclass) = io->world_class;

    // StaticMesh: only the two FNames of the FSoftObjectPath are written; the
    // FWeakObjectPtr stays null (an unresolved soft pointer) and the
    // SubPathString FString is left exactly as InitializeStruct made it.
    *reinterpret_cast<uint64_t*>(temp + io->off_staticmesh + SOFTPTR_PATH + SOFTPATH_PKG) =
        io->mesh_pkg_name;
    *reinterpret_cast<uint64_t*>(temp + io->off_staticmesh + SOFTPTR_PATH + SOFTPATH_ASSET) =
        io->mesh_asset_name;

    // ItemOffsets: written explicitly because a zeroed FTransform is scale
    // (0,0,0), which would spawn an invisible actor.
    {
        uint8_t* t = temp + io->off_itemoffsets;
        double* rot = reinterpret_cast<double*>(t + io->off_rot);
        rot[0] = 0.0; rot[1] = 0.0; rot[2] = 0.0; rot[3] = 1.0;   // identity quat
        double* tr = reinterpret_cast<double*>(t + io->off_trans);
        tr[0] = io->want_trans_x; tr[1] = io->want_trans_y; tr[2] = io->want_trans_z;
        double* sc = reinterpret_cast<double*>(t + io->off_scale);
        sc[0] = io->want_scale_x; sc[1] = io->want_scale_y; sc[2] = io->want_scale_z;
    }

    reinterpret_cast<AddRowFn>(static_cast<uintptr_t>(io->add_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr)), io->row_fname, temp);
    destroy(rs, temp, 1);
    g_free(temp);
    io->temp_freed = 1;
    io->populate_ran = 1;
}

void JobVerifyRow(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    if (!io->temp_freed) { io->err = MERR(SUB_VERIFYROW, 30); io->verifytext_ran = 2; return; }
    const uint64_t row = *reinterpret_cast<uint64_t*>(io->slot_in);
    if (!row) { io->err = MERR(SUB_VERIFYROW, 31); io->verifytext_ran = 2; return; }
    const uint32_t toff[3] = {io->off_name, io->off_shortname, io->off_description};
    uint16_t* outs[3] = {io->name_row, io->shortname_row, io->desc_row};
    for (int i = 0; i < 3; ++i) {
        io->row_textdata[i] = RD64(row + toff[i]);
        TextToChars(reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(row + toff[i])),
                    outs[i], TXT_CAP);
    }
    io->row_icon_ptr = RD64(row + io->off_inventory_icon);
    io->row_move_icon = RD64(row + io->off_move_icon);
    io->row_worldclass = RD64(row + io->off_worldclass);
    io->row_override = *reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(
        row + io->off_override_flag));
    io->row_sizex = static_cast<uint32_t>(RD32(row + io->off_override_sizex));
    io->row_sizey = static_cast<uint32_t>(RD32(row + io->off_override_sizey));
    io->row_staticmesh_pkg = RD64(row + io->off_staticmesh + SOFTPTR_PATH + SOFTPATH_PKG);
    io->row_staticmesh_asset = RD64(row + io->off_staticmesh + SOFTPTR_PATH + SOFTPATH_ASSET);
    { const double* sc = reinterpret_cast<const double*>(static_cast<uintptr_t>(
          row + io->off_itemoffsets + io->off_scale));
      io->row_scale_x = sc[0]; io->row_scale_y = sc[1]; io->row_scale_z = sc[2]; }
    io->verifymesh_ran =
        (io->row_worldclass == io->world_class &&
         io->row_staticmesh_pkg == io->mesh_pkg_name &&
         io->row_staticmesh_asset == io->mesh_asset_name &&
         io->row_move_icon == io->icon_object) ? 1u : 2u;
    io->verifytext_ran = 1;
    io->verifyicon_ran = (io->row_icon_ptr == io->icon_object) ? 1u : 2u;
}

bool Attach() {
    C5Io* io = g_io;
    const uint64_t master = io->master_item_list;
    if (RD64(master) != io->expected_composite_vtable) FAILC(SUB_ATTACH, 10, 30);
    if (RD64(master + OFF_CLASS_PRIVATE) != io->master_class) FAILC(SUB_ATTACH, 10, 31);
    if (RD64(master + io->off_rowstruct) != io->row_struct) FAILC(SUB_ATTACH, 10, 32);
    const uint64_t pt = master + io->off_parent_tables;
    const uint64_t data = RD64(pt + OFF_DATA);
    const int32_t num = RD32(pt + OFF_NUM), maxn = RD32(pt + OFF_MAX);
    io->parent_data = data; io->parent_num_before = static_cast<uint32_t>(num);
    io->parent_max = static_cast<uint32_t>(maxn);
    if (!data) FAILC(SUB_ATTACH, 11, 33);
    if (num != 1) FAILC(SUB_ATTACH, 11, 34);
    if (maxn - num < 1) FAILC(SUB_ATTACH, 11, 35);
    io->parent_elem0 = RD64(data + 0);
    io->parent_elem1_before = RD64(data + 8);
    if (io->parent_elem0 != io->item_list) FAILC(SUB_ATTACH, 11, 36);
    if (io->parent_elem1_before != 0) FAILC(SUB_ATTACH, 11, 37);
    if (!g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr)))) FAILC(SUB_ATTACH, 12, 39);
    if (RD64(io->table_ptr + io->off_rowstruct) != io->row_struct) FAILC(SUB_ATTACH, 12, 40);
    if (RD64(io->table_ptr) != io->expected_plain_vtable) FAILC(SUB_ATTACH, 12, 41);
    WR64(data + 8, io->table_ptr);
    WR32(pt + OFF_NUM, 2);
    io->parent_num_after_attach = static_cast<uint32_t>(RD32(pt + OFF_NUM));
    io->parent_elem1_after = RD64(data + 8);
    if (io->parent_num_after_attach != 2 || io->parent_elem1_after != io->table_ptr) FAILC(SUB_ATTACH, 13, 42);
    FireNeutralTrigger();
    return true;
}

void JobAttach(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    io->attach_ran = Attach() ? 1u : 2u;
}

void JobResolve(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    auto init = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->initialize_struct));
    auto destroy = reinterpret_cast<StructLifecycleFn>(static_cast<uintptr_t>(io->destroy_struct));
    void* rs = reinterpret_cast<void*>(static_cast<uintptr_t>(io->row_struct));
    uint8_t* parms = static_cast<uint8_t*>(g_malloc(SG_PARMS, 0u));
    if (!parms) { io->err = MERR(SUB_RESOLVE, 81); io->resolve_ran = 2; return; }
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
    io->resolve_worldclass = *reinterpret_cast<const uint64_t*>(d + io->off_worldclass);
    io->resolve_staticmesh_pkg = *reinterpret_cast<const uint64_t*>(
        d + io->off_staticmesh + SOFTPTR_PATH + SOFTPATH_PKG);
    io->resolve_staticmesh_asset = *reinterpret_cast<const uint64_t*>(
        d + io->off_staticmesh + SOFTPTR_PATH + SOFTPATH_ASSET);
    io->resolve_override = d[io->off_override_flag];
    io->resolve_sizex = static_cast<uint32_t>(
        *reinterpret_cast<const int32_t*>(d + io->off_override_sizex));
    io->resolve_sizey = static_cast<uint32_t>(
        *reinterpret_cast<const int32_t*>(d + io->off_override_sizey));
    { const double* sc = reinterpret_cast<const double*>(
          d + io->off_itemoffsets + io->off_scale);
      io->resolve_scale_x = sc[0]; io->resolve_scale_y = sc[1]; io->resolve_scale_z = sc[2]; }
    TextToChars(d + io->off_name, io->name_res, TXT_CAP);
    TextToChars(d + io->off_shortname, io->shortname_res, TXT_CAP);
    TextToChars(d + io->off_description, io->desc_res, TXT_CAP);
    io->resolvetext_ran = 1;
    destroy(rs, parms + SG_DETAILS, 1);
    g_free(parms);
    io->resolve_ran = 1;
}

void JobAddItem(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
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
    C5Io* io = g_io;
    JOB_ENTER();
    if (io->slot_in[0] != 1) { io->err = MERR(SUB_REMOVEITEM, 101); io->removeitem_ran = 2; return; }
    if (*reinterpret_cast<uint64_t*>(io->slot_in + 24 + IV_ID) != io->row_fname) {
        io->err = MERR(SUB_REMOVEITEM, 102); io->removeitem_ran = 2; return;
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
    C5Io* io = g_io;
    JOB_ENTER();
    const uint64_t pt = io->master_item_list + io->off_parent_tables;
    const uint64_t data = RD64(pt + OFF_DATA);
    if (!data || data != io->parent_data) { io->err = MERR(SUB_DETACH, 50); io->detach_ran = 2; return; }
    if (RD32(pt + OFF_NUM) != 2) { io->err = MERR(SUB_DETACH, 51); io->detach_ran = 2; return; }
    WR32(pt + OFF_NUM, 1);
    io->parent_num_after_detach = static_cast<uint32_t>(RD32(pt + OFF_NUM));
    FireNeutralTrigger();
    io->detach_ran = 1;
}

void JobZeroSlot(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    const uint64_t pt = io->master_item_list + io->off_parent_tables;
    const uint64_t data = RD64(pt + OFF_DATA);
    if (!data || data != io->parent_data) { io->err = MERR(SUB_ZEROSLOT, 60); io->zero_ran = 2; return; }
    if (RD32(pt + OFF_NUM) != 1) { io->err = MERR(SUB_ZEROSLOT, 61); io->zero_ran = 2; return; }
    WR64(data + 8, 0);
    io->zero_ran = (RD64(data + 8) == 0) ? 1u : 2u;
}

void JobInternRow(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    // THE AGGREGATE'S ONE NEW OPERATION.
    //
    // CreateAndRoot interns the row name once, as part of building a table.
    // An aggregate table is built ONCE and then holds many rows, so the row
    // name has to be re-interned per registration WITHOUT touching the table.
    // Everything else already works per row: AddRow and RemoveRow both key on
    // (io->table_ptr, io->row_fname), so re-pointing row_fname is the whole of
    // what a second, third or tenth item needs.
    if (!io->table_ptr || io->create_ran != 1) {
        io->err = MERR(SUB_CREATE, 20); io->internrow_ran = 2; return;
    }
    const uint64_t interned = InternName(io->row_name);
    if (!interned) { io->err = MERR(SUB_CREATE, 10); io->internrow_ran = 2; return; }
    // The neutral trigger must never be a real row name: it is removed from
    // ItemList to force the composite to rebuild, and if it collided with a row
    // that removal would delete data.
    if (interned == io->trigger_fname) {
        io->err = MERR(SUB_CREATE, 11); io->internrow_ran = 2; return;
    }
    io->row_fname = interned;
    io->internrow_ran = 1;
}

void JobRemoveRow(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    reinterpret_cast<RemoveRowFn>(static_cast<uintptr_t>(io->remove_row))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->table_ptr)), io->row_fname);
}

// Release the icon FIRST is wrong: the row still references it until the row is
// gone. The controller therefore removes the row, detaches, and only then calls
// this.
void JobReleaseIcon(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    if (!io->icon_store_handle) { io->err = MERR(SUB_RELEASE, 70); io->releaseicon_ran = 2; return; }
    const bool ok = g_store->Release(io->icon_store_handle);
    io->icon_rooted_after_release =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(io->icon_object))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    io->releaseicon_ran = ok ? 1u : 2u;
}

void JobReleaseMesh(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    if (!io->mesh_store_handle) { io->err = MERR(SUB_RELEASE, 72); io->releasemesh_ran = 2; return; }
    const bool ok = g_store->Release(io->mesh_store_handle);
    io->mesh_rooted_after_release =
        g_store->IsRooted(reinterpret_cast<void*>(static_cast<uintptr_t>(io->mesh_object))) ? 1u : 0u;
    io->owned_count = g_store->OwnedCount();
    io->releasemesh_ran = ok ? 1u : 2u;
}

void JobRelease(void*) {
    C5Io* io = g_io;
    JOB_ENTER();
    if (!io->store_handle) { io->err = MERR(SUB_RELEASE, 71); io->release_ran = 2; return; }
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
    C5Io* io = static_cast<C5Io*>(param);
    if (!io || io->magic != kMagic || io->proto != kProto) return 0xFFFFFFFFu;
    // RE-ENTRY GUARD, fail closed and touch NOTHING.
    //
    // Init used to overwrite g_io and unconditionally `new` both the asset store
    // and the dispatcher. A second Init without an intervening Shutdown would
    // therefore orphan the previous store -- and since ReleaseAll() only ever
    // walks the CURRENT store, every root it had set would stay set for the life
    // of the process -- while also leaking a dispatcher that is still ticking on
    // the game thread. Refusing is the only safe answer: there is no way to
    // adopt the previous state, and silently replacing it loses the roots.
    if (g_disp || g_store || g_io) {
        io->err = MERR(SUB_INIT, 1);
        return 0xFFFFFFFAu;
    }
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
        !io->off_rowstruct || !io->off_inventory_icon || !io->off_move_icon ||
        !io->off_worldclass || !io->off_staticmesh || !io->off_itemoffsets ||
        !io->staticmesh_class || !io->world_class) return 0xFFFFFFFDu;
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
        C5Io* io = static_cast<C5Io*>(p);                                         \
        if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;                       \
        return Misery::GameThread::Enqueue(&FN, nullptr) ? 0u : 1u;                 \
    }
EXPORT_JOB(RunCreate, JobCreate)
EXPORT_JOB(RunLoadIcon, JobLoadIcon)
EXPORT_JOB(RunLoadMesh, JobLoadMesh)
EXPORT_JOB(RunPopulate, JobPopulate)
EXPORT_JOB(RunVerifyRow, JobVerifyRow)
EXPORT_JOB(RunAttach, JobAttach)
EXPORT_JOB(RunResolve, JobResolve)
EXPORT_JOB(RunAddItem, JobAddItem)
EXPORT_JOB(RunRemoveItem, JobRemoveItem)
EXPORT_JOB(RunInternRow, JobInternRow)
EXPORT_JOB(RunRemoveRow, JobRemoveRow)
EXPORT_JOB(RunDetach, JobDetach)
EXPORT_JOB(RunZeroSlot, JobZeroSlot)
EXPORT_JOB(RunReleaseMesh, JobReleaseMesh)
EXPORT_JOB(RunReleaseIcon, JobReleaseIcon)
EXPORT_JOB(RunRelease, JobRelease)

extern "C" __declspec(dllexport) unsigned long Shutdown(void* p) {
    C5Io* io = static_cast<C5Io*>(p);
    if (!io || io != g_io || !g_disp) return 0xFFFFFFFFu;
    const uint32_t released = g_store->ReleaseAll();
    io->owned_count = g_store->OwnedCount();
    g_disp->Shutdown(5000);
    io->wait_stopped_ok = g_disp->wait_stopped_ok() ? 1u : 0u;
    io->state = static_cast<uint32_t>(g_disp->stats().state.load());
    delete g_disp; g_disp = nullptr;
    Misery::Internal::DestroyCarrier(g_carrier); g_carrier = nullptr;
    delete g_store; g_store = nullptr;
    // Clear the IO binding too, so the re-entry guard above lets a LATER Init
    // through. Without this, one Shutdown would permanently bar re-arming in
    // the same process -- which is exactly the hot-reload cycle under test.
    g_io = nullptr;
    return released;
}
